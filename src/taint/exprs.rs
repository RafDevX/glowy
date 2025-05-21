use parser::ast::{ExprNode, IndexingNode, OperandNameNode, UnaryOpKind};

use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind},
};

pub fn visit_expr<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &ExprNode<'a>,
) -> Option<LabelBacktrace<'a>> {
    match node {
        ExprNode::Name(name) => visit_operand_name(ctx, name),
        ExprNode::Literal(_) => None,
        ExprNode::Call(call) => todo!(),
        ExprNode::Indexing(indexing) => visit_indexing(ctx, indexing),
        ExprNode::UnaryOp {
            kind: UnaryOpKind::Receive,
            operand,
            location,
        } => todo!(),
        ExprNode::UnaryOp { operand, .. } => visit_expr(ctx, operand),
        ExprNode::BinaryOp {
            left,
            right,
            location,
            ..
        } => {
            let left = visit_expr(ctx, left);
            let right = visit_expr(ctx, right);

            match (&left, &right) {
                (None, None) => None,
                (Some(_), None) => left,
                (None, Some(_)) => right,
                (Some(l), Some(r)) => {
                    Some(l.union(r, LabelBacktraceKind::Expression, ctx.pin(location.clone())))
                }
            }
        }
    }
}

pub fn visit_operand_name<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &OperandNameNode<'a>,
) -> Option<LabelBacktrace<'a>> {
    // TODO: support fully-qualified names

    if let Some(symbol) = ctx.symtab().get_symbol(node.id.content()) {
        symbol
            .borrow()
            .label_backtrace()
            .and_then(|symbol_backtrace| {
                LabelBacktrace::new(
                    LabelBacktraceKind::Expression,
                    symbol_backtrace.label().clone(),
                    Some(node.id.content()),
                    ctx.pin(node.id.location()),
                    [symbol_backtrace],
                )
            })
    } else {
        ctx.report_error(AnalysisErrorKind::UnknownSymbol {
            name: node.id.clone(),
        });

        None
    }
}

pub fn visit_indexing<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &IndexingNode<'a>,
) -> Option<LabelBacktrace<'a>> {
    let expr = visit_expr(ctx, &node.expr);
    let index = visit_expr(ctx, &node.index);

    match (&expr, &index) {
        (None, None) => None,
        (Some(_), None) => expr,
        (None, Some(_)) => index,
        (Some(e), Some(i)) => Some(e.union(
            i,
            LabelBacktraceKind::Expression,
            ctx.pin(node.location.clone()),
        )),
    }
}
