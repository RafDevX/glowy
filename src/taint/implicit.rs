use std::borrow::Cow;

use parser::{
    Location, Span,
    ast::{
        AssignmentKind, BlockNode, ElseNode, ExprNode, ExprSwitchNode, ForClauseNode,
        ForHeaderNode, ForNode, ForRangeNode, FunctionResultNode, IfNode, LiteralNode,
        StatementNode, SwitchNode, TypeNode, TypeSwitchNode,
    },
};

use crate::{
    Pinned,
    context::{AnalysisContext, DeferTarget},
    labels::{LabelBacktrace, LabelBacktraceKind},
    symbols::Symbol,
    taint::{explicit, exprs},
    values::{BacktraceContainer, ValueRef},
};

pub fn visit_if<'a>(ctx: &mut AnalysisContext<'a>, node: &IfNode<'a>) {
    // Go spec: each if, for and switch is considered to be in its own
    // implicit block, so we select it here
    ctx.symtab_mut().select_next_child_scope();

    if let Some(statement) = &node.stmt {
        // simple statement to be executed before the condition is evaluated
        super::visit_statement(ctx, statement);
    }

    let pushed = if let Some(expr_backtrace) = exprs::get_expr_backtrace(ctx, &node.cond) {
        ctx.push_branch_backtrace(expr_backtrace.into_single_child(
            LabelBacktraceKind::Branch,
            None,
            ctx.pin(exprs::get_expr_location(&node.cond)),
        ));

        true
    } else {
        false
    };

    // vvv this will create another scope for the if body, which is intended
    super::visit_block(ctx, &node.then);

    match &node.otherwise {
        Some(ElseNode::If(else_if)) => visit_if(ctx, else_if),
        Some(ElseNode::Block(r#else)) => super::visit_block(ctx, r#else),
        None => {} // nothing to do
    }

    ctx.symtab_mut().select_parent_scope(); // pop implicit block

    if pushed {
        // only pop after visiting otherwise, since else is essentially an
        // implicit `if !cond`
        ctx.pop_branch_backtrace();
    }
}

pub fn visit_for<'a>(ctx: &mut AnalysisContext<'a>, node: &ForNode<'a>) {
    // Go spec: each if, for and switch is considered to be in its own
    // implicit block, so we select it here
    ctx.symtab_mut().select_next_child_scope();

    ctx.increase_branch_scope_depth();

    match &node.header {
        ForHeaderNode::Clause(clause) => {
            visit_for_clause(ctx, clause, &node.body, &node.header_location)
        }
        ForHeaderNode::Range(range) => {
            visit_for_range(ctx, range, &node.body, &node.header_location)
        }
    }

    ctx.decrease_branch_scope_depth();

    ctx.symtab_mut().select_parent_scope(); // pop implicit block
}

fn visit_for_clause<'a>(
    ctx: &mut AnalysisContext<'a>,
    clause: &ForClauseNode<'a>,
    body: &BlockNode<'a>,
    header_location: &Location,
) {
    if let Some(init) = &clause.init {
        // visit init regardless because it'll always be executed
        super::visit_statement(ctx, init);
    }

    let pushed = if let Some(cond) = &clause.cond {
        if let Some(cond_backtrace) = exprs::get_expr_backtrace(ctx, cond) {
            ctx.push_branch_backtrace(cond_backtrace.into_single_child(
                LabelBacktraceKind::Branch,
                None,
                ctx.pin(header_location.clone()),
            ));

            true
        } else {
            false
        }
    } else {
        false
    };

    // vvv this will create another scope for the for body, which is intended
    super::visit_block(ctx, body);

    // branch backtrace must remain in place while visiting post because it
    // is only executed if cond is not always false (information leakage)
    if let Some(post) = &clause.post {
        super::visit_statement(ctx, post);

        // TODO: should visit body-post multiple times until labels stabilize
    }

    if pushed {
        ctx.pop_branch_backtrace();
    }
}

fn visit_for_range<'a>(
    ctx: &mut AnalysisContext<'a>,
    range: &ForRangeNode<'a>,
    body: &BlockNode<'a>,
    header_location: &Location,
) {
    let (lhs_len, range_expr) = match range {
        ForRangeNode::Decl {
            lhs, range_expr, ..
        } => (lhs.len(), range_expr),
        ForRangeNode::Assignment {
            lhs, range_expr, ..
        } => (lhs.len(), range_expr),
        ForRangeNode::None { range_expr } => (0, range_expr),
    };

    let rhs_location = ctx.pin(exprs::get_expr_location(range_expr));
    let mut rhs_values = get_for_range_values(ctx, range_expr, rhs_location.clone());
    rhs_values.truncate(lhs_len);

    let children: Vec<_> = rhs_values
        .iter()
        .filter_map(|v| v.backtrace_at_location(rhs_location.clone()))
        .collect();

    let rhs_backtrace = LabelBacktrace::fold(
        children.iter(),
        LabelBacktraceKind::Expression,
        None,
        rhs_location,
    );

    // branch backtrace must come before assignment since it'll only take place
    // if the for loop actually iterates (i.e., range expr is non-empty); e.g.
    // ```go
    // secretArr := [0]int{}
    // x := 7
    // for x = range secretArr {}
    // // if x still == 7, secretArr is empty
    // ```
    let pushed = if let Some(branch_backtrace) = LabelBacktrace::fold(
        rhs_backtrace.as_ref(),
        LabelBacktraceKind::Branch,
        None,
        ctx.pin(header_location.clone()),
    ) {
        // necessary because body only executes if range_expr is not empty
        ctx.push_branch_backtrace(branch_backtrace);

        true
    } else {
        false
    };

    if let ForRangeNode::Decl { lhs, .. } = range {
        explicit::visit_raw_binding_decl_spec(
            ctx,
            lhs,
            rhs_values.into_iter(),
            true,
            true,
            header_location,
            &None,
        );
    } else if let ForRangeNode::Assignment { lhs, .. } = range {
        explicit::visit_raw_assignment(
            ctx,
            AssignmentKind::Simple,
            lhs,
            rhs_values.into_iter(),
            None,
            header_location,
        );
    }

    // TODO: `range ch` must update the channel's label wrt to the existing
    // branch label, since it will be depleted only in that condition

    // vvv this will create another scope for the for body, which is intended
    super::visit_block(ctx, body);

    if pushed {
        ctx.pop_branch_backtrace();
    }
}

// always visits range_expr, to trigger side effects
fn get_for_range_values<'a>(
    ctx: &mut AnalysisContext<'a>,
    range_expr: &ExprNode<'a>,
    location: Pinned<Location>,
) -> Vec<ValueRef<'a>> {
    // visit range_expr, even if just to trigger side effects
    let value = exprs::visit_single_expr(ctx, range_expr);

    // TODO: support channels

    // see table at https://go.dev/ref/spec#For_range
    if let Some(composite) = value.as_composite() {
        // 1st value key/index, 2nd value coll[k]

        let index_bt = composite.backtrace_at_location(location.clone());

        vec![ValueRef::from(index_bt), composite.get_dyn(location)]
    } else if let Some(func) = value.as_function() {
        let yield_type = func
            .signature()
            .params
            .first()
            .filter(|param| param.ids.len() == 1)
            .map(|param| &param.r#type);

        if let Some(TypeNode::Function { signature }) = yield_type {
            if let Some(FunctionResultNode::Single(TypeNode::Name {
                package: None,
                id: yield_result,
                ..
            })) = &signature.result
            {
                if yield_result.content() == "bool" {
                    let n_values: usize = signature.params.iter().map(|p| p.ids.len()).sum();

                    if n_values == 0 {
                        // note: this is wrong, we should return an empty Vec,
                        // but that would lead to an incorrect branch backtrace
                        // being set, which is worse -- branch must depend on
                        // the label of `value`, since a function might have
                        // side effects
                        return vec![ValueRef::from(value.backtrace_at_location(location))];
                    } else if n_values == 1 || n_values == 2 {
                        // FIXME: don't know how to propagate this as a sink
                    }
                }
            }
        }

        vec![]
    } else if let ExprNode::Literal(LiteralNode::Int { .. }) = range_expr {
        // this does not catch all the ints (see below), but it does catch some
        // of them (directly passed integer literals)

        vec![ValueRef::from(None)] // (literals necessarily have no label)
    } else {
        // the only options remaining (if this is a valid Go program) is either
        // a string or a (non-literal) integer, but we can't know which this is,
        // so we assume it's a string (2 values vs 1 offers more flexibility,
        // and the 1st value would coincide)

        // 1st value index, 2nd value code point
        let bt = value.backtrace_at_location(location.clone());

        vec![ValueRef::from(bt.clone()), ValueRef::from(bt)]
    }
}

pub fn visit_continue_break<'a>(
    ctx: &mut AnalysisContext<'a>,
    label: Option<&Span<'a>>,
    location: &Location,
) {
    let target = if let Some(label) = label {
        DeferTarget::LabeledLoop(label.content())
    } else {
        DeferTarget::InnermostLoop
    };

    ctx.defer_branch_backtrace(target, location.clone());
}

pub fn visit_switch<'a>(ctx: &mut AnalysisContext<'a>, node: &SwitchNode<'a>) {
    // Go spec: each if, for and switch is considered to be in its own
    // implicit block, so we select it here
    ctx.symtab_mut().select_next_child_scope();

    match node {
        SwitchNode::Expr(expr) => visit_expr_switch(ctx, expr),
        SwitchNode::Type(r#type) => visit_type_switch(ctx, r#type),
    }

    ctx.symtab_mut().select_parent_scope(); // pop implicit block
}

fn visit_expr_switch<'a>(ctx: &mut AnalysisContext<'a>, node: &ExprSwitchNode<'a>) {
    if let Some(stmt) = &node.stmt {
        // simple statement to be executed before switch
        super::visit_statement(ctx, stmt);
    }

    // Branch backtraces for each clause cannot be popped at the end of each
    // case block because their negation is implicitly asserted for all other
    // clauses. For example,
    // ```go
    // switch {
    //     case secret % 2 == 0: // do nothing
    //     case true: fmt.Println("secret is odd") // (!)
    // }
    // ```
    // here we must remember the branch backtrace introduced by the first case
    // clause even when analyzing the second clause, otherwise information about
    // the secret can be leaked.
    // Note that this is distinct from node.clauses.len()+1? because some might
    // have no backtraces (e.g., `case 3:`).
    let mut n_pushes = 0;

    if let Some(expr) = &node.expr {
        if let Some(bt) = exprs::get_expr_backtrace(ctx, expr) {
            ctx.push_branch_backtrace(bt.into_single_child(
                LabelBacktraceKind::Branch,
                None,
                ctx.pin(exprs::get_expr_location(expr)),
            ));

            n_pushes += 1;
        }
    }

    for clause in &node.clauses {
        let children: Vec<_> = clause
            .exprs
            .iter()
            .filter_map(|expr| exprs::get_expr_backtrace(ctx, expr))
            .collect();

        let folded = LabelBacktrace::fold(
            children.iter(),
            LabelBacktraceKind::Branch,
            None,
            ctx.pin(
                clause
                    .exprs
                    .first()
                    .map(exprs::get_expr_location)
                    .map(|l| l.start)
                    .unwrap_or(0)
                    ..clause
                        .exprs
                        .last()
                        .map(exprs::get_expr_location)
                        .map(|l| l.end)
                        .unwrap_or(usize::MAX),
            ),
        );

        if let Some(bt) = folded {
            ctx.push_branch_backtrace(bt);

            n_pushes += 1;
        }

        let body = if let Some(StatementNode::Fallthrough { .. }) = clause.body.last() {
            // statement visitor will reject any fallthrough statement as out of
            // place, so we omit it here before passing on the block
            Cow::Owned(clause.body[..clause.body.len() - 1].to_vec())
        } else {
            Cow::Borrowed(&clause.body)
        };

        // vvv this will create another scope for the clause body,
        // which is (probably?) intended? spec unclear at first glance
        super::visit_block(ctx, &body);
    }

    for _ in 0..n_pushes {
        ctx.pop_branch_backtrace();
    }
}

fn visit_type_switch<'a>(ctx: &mut AnalysisContext<'a>, node: &TypeSwitchNode<'a>) {
    if let Some(stmt) = &node.stmt {
        // simple statement to be executed before switch
        super::visit_statement(ctx, stmt);
    }

    let value = exprs::visit_single_expr(ctx, &node.expr);

    if let Some(id) = &node.decl {
        ctx.declare_new_symbol(Symbol::new_ref(ctx.pin(id.clone()), true, value.clone()));
    }

    let expr_location = ctx.pin(exprs::get_expr_location(&node.expr));
    let pushed = if let Some(bt) = value.backtrace_at_location(expr_location.clone()) {
        ctx.push_branch_backtrace(bt.into_single_child(
            LabelBacktraceKind::Branch,
            None,
            expr_location,
        ));

        true
    } else {
        false
    };

    for clause in &node.clauses {
        // we don't actually care about clause.types because raw types aren't
        // values and so don't have labels

        // vvv this will create another scope for the clause body,
        // which is (probably?) intended? spec unclear at first glance
        super::visit_block(ctx, &clause.body);
    }

    if pushed {
        ctx.pop_branch_backtrace();
    }
}
