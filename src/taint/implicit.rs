use std::borrow::Cow;

use parser::{
    ast::{
        AssignmentKind, BlockNode, ElseNode, ExprSwitchNode, ForClauseNode, ForHeaderNode, ForNode,
        ForRangeNode, IfNode, StatementNode, SwitchNode, TypeSwitchNode,
    },
    Location, Span,
};

use crate::{
    context::{AnalysisContext, DeferTarget},
    labels::{LabelBacktrace, LabelBacktraceKind},
    symbols::Symbol,
    taint::{
        explicit,
        exprs::{self, SingleExprLabel},
    },
};

pub fn visit_if<'a>(ctx: &mut AnalysisContext<'a>, node: &IfNode<'a>) {
    // Go spec: each if, for and switch is considered to be in its own
    // implicit block, so we select it here
    ctx.symtab_mut().select_next_child_scope();

    if let Some(statement) = &node.stmt {
        // simple statement to be executed before the condition is evaluated
        super::visit_statement(ctx, statement);
    }

    let pushed = if let Some(expr_backtrace) = exprs::visit_simple_expr(ctx, &node.cond) {
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
        if let Some(cond_backtrace) = exprs::visit_simple_expr(ctx, cond) {
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
    let range_expr = match range {
        ForRangeNode::Decl { range_expr, .. } => range_expr,
        ForRangeNode::Assignment { range_expr, .. } => range_expr,
        ForRangeNode::None { range_expr } => range_expr,
    };

    // FIXME: this is incorrect; need to decide 1 or 2 values based on table in
    // spec; see https://go.dev/ref/spec#For_range
    let rhs_backtraces = vec![exprs::visit_simple_expr(ctx, range_expr)];

    // branch backtrace must come before assignment since it'll only take place
    // if the for loop actually iterates (i.e., range expr is non-empty); e.g.
    // ```go
    // secretArr := [0]int{}
    // x := 7
    // for x = range secretArr {}
    // // if x still == 7, secretArr is empty
    // ```
    let pushed = if let Some(branch_backtrace) = LabelBacktrace::fold(
        rhs_backtraces.iter().filter_map(Option::as_ref),
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
            &rhs_backtraces,
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
            rhs_backtraces.into_iter().map(SingleExprLabel::Simple), // FIXME: not really this
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
        if let Some(bt) = exprs::visit_simple_expr(ctx, expr) {
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
            .filter_map(|expr| exprs::visit_simple_expr(ctx, expr))
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

    let pushed = if let Some(bt) = exprs::visit_simple_expr(ctx, &node.expr) {
        if let Some(id) = &node.decl {
            ctx.declare_new_symbol(Symbol::new_ref(ctx.pin(id.clone()), true, Some(bt.clone())));
        }

        ctx.push_branch_backtrace(bt.into_single_child(
            LabelBacktraceKind::Branch,
            None,
            ctx.pin(exprs::get_expr_location(&node.expr)),
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
