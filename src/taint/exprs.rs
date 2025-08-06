use parser::{
    ast::{BinaryOpKind, ExprNode, IndexingNode, LiteralNode, OperandNameNode, UnaryOpKind},
    Location,
};

use super::{channels, funcs};
use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind},
    symbols::SymbolRef,
};

pub enum ExprLabel<'a> {
    Void,
    Single(Option<LabelBacktrace<'a>>),
    Multi(Vec<Option<LabelBacktrace<'a>>>),
    MultiWithPrimary {
        primary: Option<LabelBacktrace<'a>>,
        secondary: Vec<Option<LabelBacktrace<'a>>>,
        // ^ secondary may be discarded if only a single value is accepted
    },
}

impl<'a> From<ExprLabel<'a>> for Vec<Option<LabelBacktrace<'a>>> {
    fn from(e: ExprLabel<'a>) -> Self {
        match e {
            ExprLabel::Void => vec![],
            ExprLabel::Single(bt) => vec![bt],
            ExprLabel::Multi(all) => all,
            ExprLabel::MultiWithPrimary {
                primary,
                mut secondary,
            } => {
                secondary.insert(0, primary);

                secondary
            }
        }
    }
}

pub fn visit_expr<'a>(ctx: &mut AnalysisContext<'a>, node: &ExprNode<'a>) -> ExprLabel<'a> {
    match node {
        ExprNode::Name(name) => ExprLabel::Single(visit_operand_name(ctx, name)),
        ExprNode::Literal(_) => ExprLabel::Single(None),
        ExprNode::Call(call) => funcs::visit_call(ctx, call),
        ExprNode::Indexing(indexing) => ExprLabel::Single(visit_indexing(ctx, indexing)),
        ExprNode::UnaryOp {
            kind: UnaryOpKind::Receive,
            operand,
            location,
        } => ExprLabel::Single(channels::visit_receive(ctx, operand, location)),
        ExprNode::UnaryOp { operand, .. } => ExprLabel::Single(visit_single_expr(ctx, operand)),
        ExprNode::BinaryOp {
            left,
            right,
            location,
            ..
        } => {
            let left = visit_single_expr(ctx, left);
            let right = visit_single_expr(ctx, right);

            let backtrace = LabelBacktrace::combine_options(
                left,
                right,
                LabelBacktraceKind::Expression,
                ctx.pin(location.clone()),
            );

            ExprLabel::Single(backtrace)
        }
    }
}

pub fn visit_single_expr<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &ExprNode<'a>,
) -> Option<LabelBacktrace<'a>> {
    match visit_expr(ctx, node) {
        ExprLabel::Void => {
            let location = get_expr_location(node);

            ctx.report_error(AnalysisErrorKind::UnexpectedVoidExpression {
                location: location.clone(),
            });

            None
        }
        ExprLabel::Single(bt) => bt,
        ExprLabel::Multi(all) => {
            let location = get_expr_location(node);

            ctx.report_error(AnalysisErrorKind::UnexpectedMultiValueExpression {
                location: location.clone(),
            });

            // in order to keep going, we just join all the labels
            // together, even though this is not correct Go
            LabelBacktrace::fold(
                all.iter().flatten(),
                LabelBacktraceKind::Expression,
                None,
                ctx.pin(location),
            )
        }
        ExprLabel::MultiWithPrimary { primary, .. } => primary,
    }
}

pub fn visit_operand_name<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &OperandNameNode<'a>,
) -> Option<LabelBacktrace<'a>> {
    let symbol = resolve_operand_name(ctx, node);

    if let Some(symbol) = symbol {
        symbol
            .borrow()
            .label_backtrace()
            .cloned()
            .map(|symbol_backtrace| {
                symbol_backtrace.into_single_child(
                    LabelBacktraceKind::Expression,
                    Some(node.id.content()),
                    ctx.pin(node.id.location()),
                )
            })
    } else {
        None
    }
}

/// Reports error for unknown qualifier and unknown symbol, if applicable
pub fn resolve_operand_name<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &OperandNameNode<'a>,
) -> Option<SymbolRef<'a>> {
    let symbol = if let Some(qualifier) = &node.package {
        if let Some(symbol) = ctx
            .symtab()
            .get_qualified_symbol(qualifier.content(), node.id.content())
        {
            symbol
        } else {
            ctx.report_error(AnalysisErrorKind::UnknownQualifier {
                found: qualifier.clone(),
            });

            return None;
        }
    } else {
        ctx.symtab().get_symbol(node.id.content())
    };

    if symbol.is_none() {
        ctx.report_error(AnalysisErrorKind::UnknownSymbol {
            found: node.id.clone(),
        });
    }

    symbol
}

fn visit_indexing<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &IndexingNode<'a>,
) -> Option<LabelBacktrace<'a>> {
    let name = match node.expr.as_ref() {
        ExprNode::Name(name) => name,
        ExprNode::Indexing(inner) => {
            // e.g., `arr[2][3]` -- we can't keep track of so many levels, but
            // we can respect the `arr[2]` part and try to get information on
            // that specific index; in practice, this means ignoring the `[3]`
            // and just recursing to the innermost indexing operation

            // caveat: even though we ignore the `[3]` for fine-grained array
            // analysis purposes, we still need to consider its label and merge
            // it with the recursion result, e.g. for `arr[2][secret]`

            return LabelBacktrace::combine_options(
                visit_indexing(ctx, inner),
                visit_single_expr(ctx, &node.index),
                LabelBacktraceKind::Expression,
                ctx.pin(node.location.clone()),
            );
        }
        _ => {
            // TODO: support more kinds of expressions here

            ctx.report_error(AnalysisErrorKind::InvalidIndexingBase {
                location: node.location.clone(),
            });

            return None;
        }
    };

    let Some(symbol) = resolve_operand_name(ctx, name) else {
        // no symbol found, but error already reported
        return None;
    };

    let index = try_resolve_constant_integer(&node.index)
        .map(usize::try_from)
        .and_then(Result::ok);

    let borrowed = symbol.borrow();

    borrowed.array_get(index, ctx.pin(node.location.clone()))
}

pub fn get_expr_location(node: &ExprNode<'_>) -> Location {
    match node {
        ExprNode::Name(name) => {
            let start = if let Some(package) = &name.package {
                package.location().start
            } else {
                name.id.location().start
            };

            start..name.id.location().end
        }
        ExprNode::Call(call) => call.location.clone(),
        ExprNode::Indexing(indexing) => indexing.location.clone(),
        ExprNode::UnaryOp { location, .. } | ExprNode::BinaryOp { location, .. } => {
            location.clone()
        }
        ExprNode::Literal(lit) => match lit {
            LiteralNode::Int { location, .. } => location.clone(),
            LiteralNode::Float { location, .. } => location.clone(),
            LiteralNode::Rune { location, .. } => location.clone(),
            LiteralNode::String { location, .. } => location.clone(),
        },
    }
}

// basic support for literal-only composition, e.g. `2 + 3` is recognized as 5
pub fn try_resolve_constant_integer(node: &ExprNode<'_>) -> Option<u64> {
    let result = match node {
        ExprNode::Literal(LiteralNode::Int { value, .. }) => *value,
        ExprNode::UnaryOp {
            kind: UnaryOpKind::Identity,
            operand,
            ..
        } => try_resolve_constant_integer(operand)?,
        ExprNode::BinaryOp {
            kind, left, right, ..
        } => {
            let l = try_resolve_constant_integer(left)?;
            let r = try_resolve_constant_integer(right)?;

            match kind {
                BinaryOpKind::Sum => l.saturating_add(r),
                BinaryOpKind::Diff => l.saturating_sub(r),
                BinaryOpKind::Product => l.saturating_mul(r),
                BinaryOpKind::Quotient if r != 0 => l.saturating_div(r),
                BinaryOpKind::Remainder => l % r,
                BinaryOpKind::ShiftLeft => l << r,
                BinaryOpKind::ShiftRight => l >> r,
                BinaryOpKind::BitwiseOr => l | r,
                BinaryOpKind::BitwiseAnd => l & r,
                BinaryOpKind::BitwiseXor => l ^ r,
                _ => return None,
            }
        }
        _ => return None,
    };

    Some(result)
}
