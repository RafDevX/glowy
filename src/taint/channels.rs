use parser::{
    ast::{ExprNode, SendNode},
    Location,
};

use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind},
};

use super::exprs;

pub fn visit_receive<'a>(
    ctx: &mut AnalysisContext<'a>,
    operand: &ExprNode<'a>,
    location: &Location,
) -> Option<LabelBacktrace<'a>> {
    // TODO: must update channel's label to match branch label, because
    // otherwise "has a value been read" or "has the channel been depleted" can
    // be used to exfiltrate information

    exprs::visit_single_expr(ctx, operand).and_then(|child| {
        LabelBacktrace::new(
            LabelBacktraceKind::Receive,
            child.label().clone(),
            None,
            ctx.pin(location.clone()),
            [&child],
        )
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
    let expr_backtrace = exprs::visit_single_expr(ctx, &node.expr);

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
