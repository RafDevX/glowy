use std::collections::HashMap;

use parser::{
    ast::{
        BinaryOpKind, CompositeLiteralElementListNode, CompositeLiteralElementNode, ExprNode,
        IndexingNode, LiteralNode, OperandNameNode, UnaryOpKind,
    },
    Location,
};

use super::{channels, funcs};
use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind},
    symbols::SymbolRef,
    Pinned,
};

#[derive(Debug)]
pub enum ExprLabel<'a> {
    Void,
    Simple(Option<LabelBacktrace<'a>>),
    Multi(Vec<Option<LabelBacktrace<'a>>>),
    MultiWithPrimary {
        primary: Option<LabelBacktrace<'a>>,
        secondary: Vec<Option<LabelBacktrace<'a>>>,
        // ^ secondary may be discarded if only a single value is accepted
    },
    ArrayIndices(HashMap<usize, LabelBacktrace<'a>>),
}

/// Represents an exact number of values, without any special formats.
// sadly we cannot use the `subenum` crate to make this less verbose;
// see: https://github.com/paholg/subenum/issues/48
#[derive(Debug)]
pub enum OrdinaryExprLabel<'a> {
    Void,
    Simple(Option<LabelBacktrace<'a>>),
    Multi(Vec<Option<LabelBacktrace<'a>>>),
}

impl<'a> From<OrdinaryExprLabel<'a>> for Vec<Option<LabelBacktrace<'a>>> {
    fn from(ordinary: OrdinaryExprLabel<'a>) -> Self {
        match ordinary {
            OrdinaryExprLabel::Void => vec![],
            OrdinaryExprLabel::Simple(bt) => vec![bt],
            OrdinaryExprLabel::Multi(all) => all,
        }
    }
}

impl<'a> From<OrdinaryExprLabel<'a>> for ExprLabel<'a> {
    fn from(ordinary: OrdinaryExprLabel<'a>) -> Self {
        match ordinary {
            OrdinaryExprLabel::Void => Self::Void,
            OrdinaryExprLabel::Simple(bt) => Self::Simple(bt),
            OrdinaryExprLabel::Multi(all) => Self::Multi(all),
        }
    }
}

/// Represents exactly one value.
// sadly we cannot use the `subenum` crate to make this less verbose;
// see: https://github.com/paholg/subenum/issues/48
#[derive(Debug)]
pub enum SingleExprLabel<'a> {
    Simple(Option<LabelBacktrace<'a>>),
    ArrayIndices {
        map: HashMap<usize, LabelBacktrace<'a>>,
        // don't really like Location here, but there isn't a good alternative
        // (need to be able to fold into one backtrace if required)
        location: Pinned<Location>,
    },
}

impl<'a> From<SingleExprLabel<'a>> for Option<LabelBacktrace<'a>> {
    fn from(single: SingleExprLabel<'a>) -> Self {
        match single {
            SingleExprLabel::Simple(bt) => bt,
            SingleExprLabel::ArrayIndices { map, location } => {
                LabelBacktrace::fold(map.values(), LabelBacktraceKind::Expression, None, location)
            }
        }
    }
}

pub fn visit_expr<'a>(ctx: &mut AnalysisContext<'a>, node: &ExprNode<'a>) -> ExprLabel<'a> {
    match node {
        ExprNode::Name(name) => ExprLabel::Simple(visit_operand_name(ctx, name)),
        ExprNode::Literal(lit) => visit_literal(ctx, lit),
        ExprNode::Call(call) => funcs::visit_call(ctx, call).into(),
        ExprNode::Indexing(indexing) => ExprLabel::Simple(visit_indexing(ctx, indexing)),
        ExprNode::UnaryOp {
            kind: UnaryOpKind::Receive,
            operand,
            location,
        } => ExprLabel::Simple(channels::visit_receive(ctx, operand, location)),
        ExprNode::UnaryOp { operand, .. } => ExprLabel::Simple(visit_simple_expr(ctx, operand)),
        ExprNode::BinaryOp {
            left,
            right,
            location,
            ..
        } => {
            let left = visit_simple_expr(ctx, left);
            let right = visit_simple_expr(ctx, right);

            let backtrace = LabelBacktrace::combine_options(
                left,
                right,
                LabelBacktraceKind::Expression,
                ctx.pin(location.clone()),
            );

            ExprLabel::Simple(backtrace)
        }
    }
}

pub fn visit_single_expr<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &ExprNode<'a>,
) -> SingleExprLabel<'a> {
    match visit_expr(ctx, node) {
        // already a single value
        ExprLabel::Simple(bt) => SingleExprLabel::Simple(bt),
        ExprLabel::ArrayIndices(map) => SingleExprLabel::ArrayIndices {
            map,
            location: ctx.pin(get_expr_location(node)),
        },

        // not a single value, need to convert and maybe error
        ExprLabel::Void => {
            ctx.report_error(AnalysisErrorKind::UnexpectedVoidExpression {
                location: get_expr_location(node),
            });

            SingleExprLabel::Simple(None)
        }
        ExprLabel::Multi(all) => {
            let location = get_expr_location(node);

            ctx.report_error(AnalysisErrorKind::UnexpectedMultiValueExpression {
                location: location.clone(),
            });

            // in order to keep going, we just join all the labels
            // together, even though this is not correct Go
            SingleExprLabel::Simple(LabelBacktrace::fold(
                all.iter().flatten(),
                LabelBacktraceKind::Expression,
                None,
                ctx.pin(location),
            ))
        }
        ExprLabel::MultiWithPrimary { primary, .. } => SingleExprLabel::Simple(primary),
    }
}

pub fn visit_simple_expr<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &ExprNode<'a>,
) -> Option<LabelBacktrace<'a>> {
    visit_single_expr(ctx, node).into()
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

fn visit_literal<'a>(ctx: &mut AnalysisContext<'a>, node: &LiteralNode<'a>) -> ExprLabel<'a> {
    match node {
        LiteralNode::Int { .. }
        | LiteralNode::Float { .. }
        | LiteralNode::Rune { .. }
        | LiteralNode::String { .. } => ExprLabel::Simple(None),
        LiteralNode::Array {
            values, location, ..
        }
        | LiteralNode::Slice {
            values, location, ..
        } => {
            // Array length must be a constant so we don't need to visit it to
            // trigger side-effects (there aren't any); we can focus on values
            visit_array_literal(ctx, values, location)
        }
    }
}

// for analysis purposes, slices are treated as arrays
fn visit_array_literal<'a>(
    ctx: &mut AnalysisContext<'a>,
    values: &CompositeLiteralElementListNode<'a, usize>,
    location: &Location,
) -> ExprLabel<'a> {
    let mut map = HashMap::new();

    let mut next_default_key = 0;
    for (opt_key, el) in values {
        if let Some(bt) = visit_array_literal_element(ctx, el, location) {
            let key = opt_key.as_ref().copied().unwrap_or(next_default_key);
            next_default_key = key + 1;

            map.insert(key, bt);
        }
    }

    ExprLabel::ArrayIndices(map)
}

// we only support 1 level of depth, so here we just recursively fold up these
// higher dimensions into one single level
fn visit_array_literal_element<'a, K>(
    ctx: &mut AnalysisContext<'a>,
    node: &CompositeLiteralElementNode<'a, K>,
    location: &Location,
) -> Option<LabelBacktrace<'a>> {
    match &node {
        CompositeLiteralElementNode::Expr(expr) => visit_simple_expr(ctx, expr),
        CompositeLiteralElementNode::Nested(items) => {
            let children: Vec<_> = items
                .iter()
                .map(|(_, v)| v)
                .filter_map(|el| visit_array_literal_element(ctx, el, location))
                .collect();

            if children.is_empty() {
                // quicker escape to avoid clones et al. if they're unnecessary
                return None;
            }

            LabelBacktrace::fold(
                children.iter(),
                LabelBacktraceKind::Expression,
                None,
                ctx.pin(location.clone()),
            )
        }
    }
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
                visit_simple_expr(ctx, &node.index),
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
            LiteralNode::Array { location, .. } => location.clone(),
            LiteralNode::Slice { location, .. } => location.clone(),
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
