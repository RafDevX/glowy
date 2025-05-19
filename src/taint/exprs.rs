use parser::ast::ExprNode;

use crate::{context::AnalysisContext, labels::LabelBacktrace};

pub fn visit_expr<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &ExprNode<'a>,
) -> Option<LabelBacktrace<'a>> {
    // TODO

    None
}
