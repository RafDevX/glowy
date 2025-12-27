use std::collections::HashMap;

use parser::{
    Location,
    ast::{
        CompositeLiteralElementListNode, CompositeLiteralElementNode, ExprNode, IndexingNode,
        LiteralNode, OperandNameNode, SelectionNode, StructLiteralFieldsNode, TypeNode,
        UnaryOpKind,
    },
};

use super::{channels, funcs};
use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind},
    symbols::SymbolRef,
    values::{
        BacktraceContainer, CompositeValue, ExpandableValue, SelfAwareBacktraceContainer,
        SimpleConstValue, Value, ValueRef,
    },
};

pub fn visit_expr<'a>(ctx: &mut AnalysisContext<'a>, node: &ExprNode<'a>) -> Vec<ValueRef<'a>> {
    let single = match node {
        ExprNode::Name(name) => visit_operand_name(ctx, name),
        ExprNode::Literal(lit) => visit_literal(ctx, lit),
        ExprNode::Call(call) => return funcs::visit_call(ctx, call),
        ExprNode::Make(make) => funcs::builtins::visit_make(ctx, make),
        ExprNode::Selection(selection) => visit_selection(ctx, selection),
        ExprNode::Indexing(indexing) => visit_indexing(ctx, indexing),
        ExprNode::Conversion(conversion) => visit_single_expr(ctx, &conversion.expr),
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

pub fn visit_multi_exprs<'a>(
    ctx: &mut AnalysisContext<'a>,
    nodes: &[ExprNode<'a>],
) -> Vec<ValueRef<'a>> {
    if let [single] = nodes {
        // only one expression, which might end up being:
        // - a function call returning multiple values, e.g. `x, y := f()`; or
        // - just a normal expression, corresponding to a single value, but in
        //   that case visit_expr will wrap it in a vec so we're all good

        visit_expr(ctx, single)
    } else {
        // single multiple expressions were provided, we know for sure that each
        // of them must yield a single value

        nodes
            .iter()
            .map(|expr| visit_single_expr(ctx, expr))
            .collect()
    }
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
        return ValueRef::new_unknown();
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
    let symbol = if let Some(qualifier) = node.package {
        match ctx
            .symtab()
            .get_qualified_symbol(qualifier.content(), node.id.content())
        {
            Some(Some(symbol)) => symbol,
            Some(None) => {
                // this is likely the accessing of blackbox package for which we
                // do not actually have the source, so we just return None now
                // without actually reporting any error

                return None;
            }
            None => {
                ctx.report_error(AnalysisErrorKind::UnknownQualifier { found: qualifier });

                return None;
            }
        }
    } else {
        ctx.symtab().get_symbol(node.id.content())
    };

    if symbol.is_none() {
        ctx.report_error(AnalysisErrorKind::UnknownSymbol { found: node.id });
    }

    symbol
}

fn visit_literal<'a>(ctx: &mut AnalysisContext<'a>, node: &LiteralNode<'a>) -> ValueRef<'a> {
    match node {
        LiteralNode::Int { .. }
        | LiteralNode::Float { .. }
        | LiteralNode::Rune { .. }
        | LiteralNode::String { .. } => ValueRef::from(None),
        LiteralNode::Function {
            signature,
            body,
            location,
        } => funcs::visit_function_literal(ctx, signature, body, location),
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
        } => ValueRef::from(Value::Map(visit_map_composite_literal(
            ctx, values, location,
        ))),
        LiteralNode::Struct {
            r#type,
            fields,
            location,
            ..
        } => ValueRef::from(Value::Struct(visit_struct_composite_literal(
            ctx, fields, r#type, location,
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
            next_default_key += 1;

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

fn visit_map_composite_literal<'a>(
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

        let const_key = opt_key
            .as_ref()
            .and_then(SimpleConstValue::try_resolve_from_expr);

        if let Some(const_key) = const_key {
            map.insert(const_key, value);
        } else {
            if let Some(dyn_key) = opt_key {
                others.push(visit_single_expr(ctx, dyn_key));
            }

            others.push(value);
        }
    }

    CompositeValue::new(map, others, ctx.pin(location.clone()))
}

fn visit_struct_composite_literal<'a>(
    ctx: &mut AnalysisContext<'a>,
    fields: &StructLiteralFieldsNode<'a>,
    r#type: &TypeNode<'a>,
    location: &Location,
) -> CompositeValue<'a, String> {
    let mut map = HashMap::new();
    let mut others = Vec::new();

    match fields {
        StructLiteralFieldsNode::Keyed(entries) => {
            for (field_name, element) in entries {
                let value = visit_array_literal_element(ctx, element, location);

                if value.is_bottom() {
                    // we don't need to bloat the HashMap with None backtraces
                    continue;
                }

                if map.insert(field_name.content().to_owned(), value).is_some() {
                    // duplicate; error
                    ctx.report_error(AnalysisErrorKind::DuplicateStructFieldName {
                        duplicate: *field_name,
                    });
                }
            }
        }
        StructLiteralFieldsNode::Exhaustive(entries) => {
            // we try to extract field names from the type information, but in
            // most cases this will not be possible, and in those cases we can
            // only pass the field information as "others" (which will become
            // the basis for the dyn backtrace of the composite value)

            let names = if let TypeNode::Struct { fields } = r#type {
                let candidate: Vec<_> = fields
                    .iter()
                    .flat_map(|f| f.ids.iter())
                    .map(Option::as_ref)
                    .collect();

                if candidate.len() == entries.len() {
                    Some(candidate)
                } else {
                    // this should never happen, but oh well
                    None
                }
            } else {
                None
            };

            if let Some(names) = names {
                for (name, element) in names.iter().copied().zip(entries) {
                    let value = visit_array_literal_element(ctx, element, location);

                    if let Some(&name) = name {
                        // happy path: we know the field name!
                        if map.insert(name.content().to_owned(), value).is_some() {
                            // duplicate; error
                            // (should never happen, but we don't validate types)
                            ctx.report_error(AnalysisErrorKind::DuplicateStructFieldName {
                                duplicate: name,
                            });
                        }
                    } else {
                        // padding (blank "_" identifier); never accessible so
                        // we don't need to care about it besides visiting to
                        // trigger side effects (which we have already done
                        // above) -- padding fields are always the zero-value
                        // and are never initialized even if an expression is
                        // provided: try running this in the Go playground
                        // ```go
                        // x := struct{ x, _, y int }{4, 3, -1}
                        // fmt.Println(x) // prints {4 0 -1}
                        // ```
                    }
                }
            } else {
                // nothing to do, we cannot know field names, so we just
                // approximate by merging all the provided values together
                for element in entries {
                    let value = visit_array_literal_element(ctx, element, location);

                    others.push(value);
                }
            }
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

fn visit_selection<'a>(ctx: &mut AnalysisContext<'a>, node: &SelectionNode<'a>) -> ValueRef<'a> {
    let base = visit_single_expr(ctx, &node.base);

    let Some(r#struct) = base.as_struct() else {
        ctx.report_error(AnalysisErrorKind::InvalidSelectionBase {
            location: node.location.clone(),
        });

        return ValueRef::from(None);
    };

    r#struct.get_const(
        node.selector.content().to_owned(),
        ctx.pin(node.location.clone()),
    )
}

fn visit_indexing<'a>(ctx: &mut AnalysisContext<'a>, node: &IndexingNode<'a>) -> ValueRef<'a> {
    let base = visit_single_expr(ctx, &node.base);

    let Some(composite) = base.as_composite() else {
        ctx.report_error(AnalysisErrorKind::InvalidIndexingBase {
            location: node.location.clone(),
        });

        return ValueRef::from(None);
    };

    let index = SimpleConstValue::try_resolve_from_expr(&node.index);

    let result = if let Some(index) = index {
        composite.get_const(index, ctx.pin(node.location.clone()))
    } else {
        composite.get_dyn(ctx.pin(node.location.clone()))
    };

    if base.is_map() {
        // indexing a map returns a second value corresponding to whether the
        // key was or not present in the map. here, we assume that this presence
        // value has the same label as the actual returned value
        let presence = result.backtrace_at_location(ctx.pin(node.location.clone()));

        ValueRef::from(Value::Expandable(ExpandableValue::new(
            result,
            vec![ValueRef::from(presence)],
        )))
    } else {
        result
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
        ExprNode::Make(make) => make.location.clone(),
        ExprNode::Selection(selection) => selection.location.clone(),
        ExprNode::Indexing(indexing) => indexing.location.clone(),
        ExprNode::Conversion(conversion) => conversion.location.clone(),
        ExprNode::UnaryOp { location, .. } | ExprNode::BinaryOp { location, .. } => {
            location.clone()
        }
        ExprNode::Literal(lit) => match lit {
            LiteralNode::Int { location, .. } => location.clone(),
            LiteralNode::Float { location, .. } => location.clone(),
            LiteralNode::Rune { location, .. } => location.clone(),
            LiteralNode::String { location, .. } => location.clone(),
            LiteralNode::Function { location, .. } => location.clone(),
            LiteralNode::Array { location, .. } => location.clone(),
            LiteralNode::Slice { location, .. } => location.clone(),
            LiteralNode::Map { location, .. } => location.clone(),
            LiteralNode::Struct { location, .. } => location.clone(),
        },
    }
}
