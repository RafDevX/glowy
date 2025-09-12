use parser::{
    Location,
    ast::{ExprNode, SendNode},
};

use super::exprs;
use crate::{
    context::AnalysisContext,
    labels::LabelBacktraceKind,
    taint::explicit::LeftValue,
    values::{SelfAwareBacktraceContainer, ValueRef},
};

pub fn visit_receive<'a>(
    ctx: &mut AnalysisContext<'a>,
    operand: &ExprNode<'a>,
    location: &Location,
) -> ValueRef<'a> {
    // TODO: must update channel's label to match branch label, because
    // otherwise "has a value been read" or "has the channel been depleted" can
    // be used to exfiltrate information

    exprs::visit_single_expr(ctx, operand).nest_backtrace(
        LabelBacktraceKind::Receive,
        None,
        ctx.pin(location.clone()),
        vec![],
    )
}

pub fn visit_send<'a>(ctx: &mut AnalysisContext<'a>, node: &SendNode<'a>) {
    // vvv TODO: deal with annotation
    let explicit_backtrace = None;

    let base = exprs::visit_single_expr(ctx, &node.expr);

    // we take send as syntactic sugar for a complex assignment
    node.expr.assign(
        ctx,
        LabelBacktraceKind::Send,
        base,
        false, // don't overwrite ever
        explicit_backtrace,
        &node.location,
    );
}
