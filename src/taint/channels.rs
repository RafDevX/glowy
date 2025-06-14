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

        let location =
            exprs::get_expr_location(&node.channel).unwrap_or_else(|| node.location.clone());

        ctx.report_error(AnalysisErrorKind::IllegalChannelExpression { location });

        return;
    };

    let Some(symbol) = exprs::resolve_operand_name(ctx, name) else {
        // error already reported
        return;
    };

    // TODO: branch backtrace

    let children: Vec<_> = [
        symbol.borrow().label_backtrace().cloned(),
        exprs::visit_single_expr(ctx, &node.expr),
    ]
    .into_iter()
    .flatten()
    .collect();

    let backtrace = LabelBacktrace::fold(
        &children,
        LabelBacktraceKind::Send,
        Some(name.id.content()),
        ctx.pin(node.location.clone()),
    );

    symbol.borrow_mut().set_label_backtrace(backtrace);
}
