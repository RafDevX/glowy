use std::collections::HashMap;

use parser::{
    Location,
    ast::{
        CompositeLiteralElementListNode, CompositeLiteralElementNode, ExprNode, IndexingNode,
        LiteralNode, OperandNameNode, UnaryOpKind,
    },
};

use super::{channels, funcs};
use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind},
    symbols::SymbolRef,
    values::{
        BacktraceContainer, CompositeValue, SelfAwareBacktraceContainer, SimpleConstValue, Value,
        ValueRef,
    },
};

pub fn visit_expr<'a>(ctx: &mut AnalysisContext<'a>, node: &ExprNode<'a>) -> Vec<ValueRef<'a>> {
    let single = match node {
        ExprNode::Name(name) => visit_operand_name(ctx, name),
        ExprNode::Literal(lit) => visit_literal(ctx, lit),
        ExprNode::Call(call) => return funcs::visit_call(ctx, call),
        ExprNode::Indexing(indexing) => visit_indexing(ctx, indexing),
        ExprNode::UnaryOp {
            kind: UnaryOpKind::Receive,
            operand,
            location,
        } => channels::visit_receive(ctx, operand, location),
        ExprNode::UnaryOp { operand, .. } => visit_single_expr(ctx, operand),
        ExprNode::BinaryOp {
            left,
            right,
            location,
            ..
        } => {
            let left_location = ctx.pin(get_expr_location(left));
            let right_location = ctx.pin(get_expr_location(right));

            let left = visit_single_expr(ctx, left).backtrace_at_location(left_location);
            let right = visit_single_expr(ctx, right).backtrace_at_location(right_location);

            let backtrace = LabelBacktrace::combine_options(
                left,
                right,
                LabelBacktraceKind::Expression,
                ctx.pin(location.clone()),
            );

            ValueRef::from(backtrace)
        }
    };

    vec![single]
}

pub fn visit_single_expr<'a>(ctx: &mut AnalysisContext<'a>, node: &ExprNode<'a>) -> ValueRef<'a> {
    let mut result = visit_expr(ctx, node);

    if result.is_empty() {
        ctx.report_error(AnalysisErrorKind::UnexpectedVoidExpression {
            location: get_expr_location(node),
        });
    } else if result.len() > 1 {
        ctx.report_error(AnalysisErrorKind::UnexpectedMultiValueExpression {
            location: get_expr_location(node),
        });
    } else {
        return result.pop().unwrap(); // already checked
    }

    ValueRef::from(None)
}

pub fn get_expr_backtrace<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &ExprNode<'a>,
) -> Option<LabelBacktrace<'a>> {
    let location = ctx.pin(get_expr_location(node));

    visit_single_expr(ctx, node).backtrace_at_location(location)
}

pub fn visit_operand_name<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &OperandNameNode<'a>,
) -> ValueRef<'a> {
    let Some(symbol) = resolve_operand_name(ctx, node) else {
        // error already reported
        return ValueRef::from(None);
    };

    let borrowed = symbol.borrow();

    borrowed.value().nest_backtrace(
        LabelBacktraceKind::Expression,
        Some(node.id.content()),
        ctx.pin(node.id.location()),
        [],
    )
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

fn visit_literal<'a>(ctx: &mut AnalysisContext<'a>, node: &LiteralNode<'a>) -> ValueRef<'a> {
    match node {
        LiteralNode::Int { .. }
        | LiteralNode::Float { .. }
        | LiteralNode::Rune { .. }
        | LiteralNode::String { .. } => ValueRef::from(None),
        LiteralNode::Array {
            values, location, ..
        } => ValueRef::from(Value::Array(visit_integer_keyed_composite_literal(
            ctx, values, location,
        ))),
        LiteralNode::Slice {
            values, location, ..
        } => {
            // Array length must be a constant so we don't need to visit it to
            // trigger side-effects (there aren't any); we can focus on values
            ValueRef::from(Value::Slice(visit_integer_keyed_composite_literal(
                ctx, values, location,
            )))
        }
        LiteralNode::Map {
            values, location, ..
        } => ValueRef::from(Value::Map(visit_generic_composite_literal(
            ctx, values, location,
        ))),
    }
}

fn visit_integer_keyed_composite_literal<'a>(
    ctx: &mut AnalysisContext<'a>,
    values: &CompositeLiteralElementListNode<'a>,
    location: &Location,
) -> CompositeValue<'a, u64> {
    let mut map = HashMap::new();
    let mut others = Vec::new();

    let mut next_default_key = 0;
    for (opt_key, el) in values {
        let value = visit_array_literal_element(ctx, el, location);

        if value.is_bottom() {
            // we don't need to bloat the HashMap with None backtraces
            continue;
        }

        let key = if let Some(expr) = opt_key {
            if let Some(SimpleConstValue::Integer(int)) =
                SimpleConstValue::try_resolve_from_expr(expr)
            {
                Some(int)
            } else {
                // should not happen for arrays/slices, but you never know
                // (more complex const expressions won't be resolved)
                None
            }
        } else {
            Some(next_default_key)
        };

        if let Some(key) = key {
            next_default_key = key + 1;

            map.insert(key, value);
        } else {
            next_default_key += 1; // no proper answer on what to do here...

            others.push(value);
        }
    }

    CompositeValue::new(map, others, ctx.pin(location.clone()))
}

fn visit_generic_composite_literal<'a>(
    ctx: &mut AnalysisContext<'a>,
    values: &CompositeLiteralElementListNode<'a>,
    location: &Location,
) -> CompositeValue<'a, SimpleConstValue> {
    let mut map = HashMap::new();
    let mut others = Vec::new();

    for (opt_key, el) in values {
        let value = visit_array_literal_element(ctx, el, location);

        if value.is_bottom() {
            // we don't need to bloat the HashMap with None backtraces
            continue;
        }

        let key = opt_key
            .as_ref()
            .and_then(SimpleConstValue::try_resolve_from_expr);

        if let Some(key) = key {
            map.insert(key, value);
        } else {
            others.push(value);
        }
    }

    CompositeValue::new(map, others, ctx.pin(location.clone()))
}

fn visit_array_literal_element<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &CompositeLiteralElementNode<'a>,
    location: &Location,
) -> ValueRef<'a> {
    match &node {
        CompositeLiteralElementNode::Expr(expr) => visit_single_expr(ctx, expr),
        CompositeLiteralElementNode::Nested(items) => {
            let mut values: Vec<_> = items
                .iter()
                .map(|(_, v)| v)
                .map(|el| visit_array_literal_element(ctx, el, location))
                .filter(|v| !v.is_bottom())
                .collect();

            if values.is_empty() {
                // quicker escape to avoid clones et al. if they're unnecessary
                ValueRef::from(None)
            } else if values.len() == 1 {
                values.pop().unwrap()
            } else {
                let backtraces: Vec<_> = values
                    .iter()
                    .filter_map(|v| v.backtrace_at_location(ctx.pin(location.clone())))
                    .collect();

                ValueRef::from(LabelBacktrace::fold(
                    &backtraces,
                    LabelBacktraceKind::Expression,
                    None,
                    ctx.pin(location.clone()),
                ))
            }
        }
    }
}

fn visit_indexing<'a>(ctx: &mut AnalysisContext<'a>, node: &IndexingNode<'a>) -> ValueRef<'a> {
    let base = visit_single_expr(ctx, &node.expr);

    let Some(composite) = base.as_composite() else {
        ctx.report_error(AnalysisErrorKind::InvalidIndexingBase {
            location: node.location.clone(),
        });

        return ValueRef::from(None);
    };

    let index = SimpleConstValue::try_resolve_from_expr(&node.index);

    if let Some(index) = index {
        composite.get_const(index, ctx.pin(node.location.clone()))
    } else {
        composite.get_dyn(ctx.pin(node.location.clone()))
    }
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
            LiteralNode::Map { location, .. } => location.clone(),
        },
    }
}
