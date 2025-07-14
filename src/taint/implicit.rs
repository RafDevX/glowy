use parser::{
    ast::{
        AssignmentKind, BlockNode, ElseNode, ForClauseNode, ForHeaderNode, ForNode, ForRangeNode,
        IfNode,
    },
    Location,
};

use crate::{
    context::AnalysisContext,
    labels::{LabelBacktrace, LabelBacktraceKind},
    taint::{explicit, exprs},
};

pub fn visit_if<'a>(ctx: &mut AnalysisContext<'a>, node: &IfNode<'a>) {
    let pushed = if let Some(expr_backtrace) = exprs::visit_single_expr(ctx, &node.cond) {
        ctx.push_branch_backtrace(
            LabelBacktrace::new(
                LabelBacktraceKind::Branch,
                expr_backtrace.label().clone(),
                None,
                ctx.pin(exprs::get_expr_location(&node.cond)),
                &[expr_backtrace],
            )
            .unwrap(), // safe since expr_backtrace exists (label is not Bottom)
        );

        true
    } else {
        false
    };

    // Go spec: each if, for and switch is considered to be in its own
    // implicit block, so we select it here
    ctx.symtab_mut().select_next_child_scope();

    // TODO: visit the if's simple statement, if any

    // vvv this will create another scope for the if body, which is intended
    super::visit_block(ctx, &node.then);

    match &node.otherwise {
        Some(ElseNode::If(else_if)) => visit_if(ctx, else_if),
        Some(ElseNode::Block(r#else)) => super::visit_block(ctx, r#else),
        None => {} // nothing to do
    }

    ctx.symtab_mut().select_parent_scope(); // pop implicit block

    if pushed {
        ctx.pop_branch_backtrace();
    }
}

pub fn visit_for<'a>(ctx: &mut AnalysisContext<'a>, node: &ForNode<'a>) {
    // Go spec: each if, for and switch is considered to be in its own
    // implicit block, so we select it here
    ctx.symtab_mut().select_next_child_scope();

    match &node.header {
        ForHeaderNode::Clause(clause) => {
            visit_for_clause(ctx, clause, &node.body, &node.header_location)
        }
        ForHeaderNode::Range(range) => {
            visit_for_range(ctx, range, &node.body, &node.header_location)
        }
    }

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
        if let Some(cond_backtrace) = exprs::visit_single_expr(ctx, cond) {
            ctx.push_branch_backtrace(
                LabelBacktrace::new(
                    LabelBacktraceKind::Branch,
                    cond_backtrace.label().clone(),
                    None,
                    ctx.pin(header_location.clone()),
                    &[cond_backtrace],
                )
                .unwrap(), // safe since cond_backtrace exists (label != Bottom)
            );

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

    let rhs_backtraces = exprs::visit_expr(ctx, range_expr);

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
            &rhs_backtraces,
            header_location,
        );
    }

    // TODO: `range ch` must update the channel's label wrt to the existing
    // branch label, since it will be depleted only in that condition

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

    // vvv this will create another scope for the for body, which is intended
    super::visit_block(ctx, body);

    if pushed {
        ctx.pop_branch_backtrace();
    }
}
