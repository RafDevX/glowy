use parser::{ast::ExprNode, Location};

use crate::{
    context::AnalysisContext,
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
