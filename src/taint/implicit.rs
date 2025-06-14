use parser::ast::{ElseNode, IfNode};

use crate::{
    context::AnalysisContext,
    labels::{LabelBacktrace, LabelBacktraceKind},
    taint::exprs,
};

pub fn visit_if<'a>(ctx: &mut AnalysisContext<'a>, node: &IfNode<'a>) {
    let pushed = if let Some(expr_backtrace) = exprs::visit_single_expr(ctx, &node.cond) {
        let location = exprs::get_expr_location(&node.cond)
            .map(|l| ctx.pin(l))
            .unwrap_or_else(|| expr_backtrace.location().clone());

        ctx.push_branch_backtrace(
            LabelBacktrace::new(
                LabelBacktraceKind::Branch,
                expr_backtrace.label().clone(),
                None,
                location,
                &[expr_backtrace],
            )
            .unwrap(), // safe since expr_backtrace exists (label is not Bottom)
        );

        true
    } else {
        false
    };

    // Go spec: each if, for and switch is considered to be
    // in its own implicit block, so we select it here
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
