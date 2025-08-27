use parser::{
    ast::{ExprNode, SendNode},
    Location,
};

use super::exprs;
use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind},
};

pub fn visit_receive<'a>(
    ctx: &mut AnalysisContext<'a>,
    operand: &ExprNode<'a>,
    location: &Location,
) -> Option<LabelBacktrace<'a>> {
    // TODO: must update channel's label to match branch label, because
    // otherwise "has a value been read" or "has the channel been depleted" can
    // be used to exfiltrate information

    exprs::visit_simple_expr(ctx, operand).map(|child| {
        child.into_single_child(LabelBacktraceKind::Receive, None, ctx.pin(location.clone()))
    })
}

pub fn visit_send<'a>(ctx: &mut AnalysisContext<'a>, node: &SendNode<'a>) {
    // TODO: deal with annotation

    let ExprNode::Name(name) = &node.channel else {
        // TODO: support more indirect kinds of channel expressions

        ctx.report_error(AnalysisErrorKind::IllegalChannelExpression {
            location: exprs::get_expr_location(&node.channel),
        });

        return;
    };

    let Some(symbol) = exprs::resolve_operand_name(ctx, name) else {
        // error already reported
        return;
    };

    let borrowed = symbol.borrow();
    let expr_backtrace = exprs::visit_simple_expr(ctx, &node.expr);

    let backtrace = LabelBacktrace::fold(
        [
            borrowed.label_backtrace(),
            expr_backtrace.as_ref(),
            ctx.branch_backtrace(),
        ]
        .into_iter()
        .flatten(),
        LabelBacktraceKind::Send,
        Some(name.id.content()),
        ctx.pin(node.location.clone()),
    );

    symbol.borrow_mut().set_label_backtrace(backtrace);
}
