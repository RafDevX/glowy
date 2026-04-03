use std::collections::HashMap;

use parser::{
    Location,
    ast::{
        CompositeLiteralElementListNode, CompositeLiteralElementNode, LiteralNode,
        StructLiteralFieldsNode, TypeNode,
    },
};

use crate::{
    Pinned,
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind},
    taint::funcs,
    values::{BacktraceContainer, CompositeValue, SimpleConstValue, Value, ValueRef},
};

pub fn visit_literal<'a>(ctx: &mut AnalysisContext<'a>, node: &LiteralNode<'a>) -> ValueRef<'a> {
    match node {
        LiteralNode::Int { location, .. }
        | LiteralNode::Float { location, .. }
        | LiteralNode::Rune { location, .. }
        | LiteralNode::String { location, .. } => ValueRef::new_bottom(ctx.pin(location.clone())),
        LiteralNode::Function {
            signature,
            body,
            location,
        } => funcs::visit_function_literal(ctx, signature, body, location),
        LiteralNode::Array {
            values, location, ..
        } => {
            let location = ctx.pin(location.clone());

            let value = Value::Array(visit_integer_keyed_composite_literal(
                ctx,
                values,
                location.clone(),
            ));

            ValueRef::new(value, location)
        }
        LiteralNode::Slice {
            values, location, ..
        } => {
            // Array length must be a constant so we don't need to visit it to
            // trigger side-effects (there aren't any); we can focus on values

            let location = ctx.pin(location.clone());

            let value = Value::Slice(visit_integer_keyed_composite_literal(
                ctx,
                values,
                location.clone(),
            ));

            ValueRef::new(value, location)
        }
        LiteralNode::Map {
            values, location, ..
        } => {
            let location = ctx.pin(location.clone());

            let value = Value::Map(visit_map_composite_literal(ctx, values, location.clone()));

            ValueRef::new(value, location)
        }
        LiteralNode::Struct {
            r#type,
            fields,
            location,
            ..
        } => {
            let location = ctx.pin(location.clone());

            let value = Value::Struct(visit_struct_composite_literal(
                ctx,
                fields,
                r#type,
                location.clone(),
            ));

            ValueRef::new(value, location)
        }
    }
}

fn visit_integer_keyed_composite_literal<'a>(
    ctx: &mut AnalysisContext<'a>,
    values: &CompositeLiteralElementListNode<'a>,
    location: Pinned<Location>,
) -> CompositeValue<'a, u64> {
    let mut map = HashMap::new();
    let mut others = Vec::new();

    let mut next_default_key = 0;
    for (opt_key, el) in values {
        let value = visit_array_literal_element(ctx, el, &location);

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

    CompositeValue::new(map, others, location)
}

fn visit_map_composite_literal<'a>(
    ctx: &mut AnalysisContext<'a>,
    values: &CompositeLiteralElementListNode<'a>,
    location: Pinned<Location>,
) -> CompositeValue<'a, SimpleConstValue> {
    let mut map = HashMap::new();
    let mut others = Vec::new();

    for (opt_key, el) in values {
        let value = visit_array_literal_element(ctx, el, &location);

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
                others.push(super::visit_single_expr(ctx, dyn_key));
            }

            others.push(value);
        }
    }

    CompositeValue::new(map, others, location)
}

fn visit_struct_composite_literal<'a>(
    ctx: &mut AnalysisContext<'a>,
    fields: &StructLiteralFieldsNode<'a>,
    r#type: &TypeNode<'a>,
    location: Pinned<Location>,
) -> CompositeValue<'a, String> {
    let mut map = HashMap::new();
    let mut others = Vec::new();

    match fields {
        StructLiteralFieldsNode::Keyed(entries) => {
            for (field_name, element) in entries {
                let value = visit_array_literal_element(ctx, element, &location);

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

            let names = if let TypeNode::Struct {
                fields: type_fields,
            } = r#type
            {
                let candidate: Vec<_> = type_fields
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
                    let value = visit_array_literal_element(ctx, element, &location);

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
                    let value = visit_array_literal_element(ctx, element, &location);

                    others.push(value);
                }
            }
        }
    }

    CompositeValue::new(map, others, location)
}

fn visit_array_literal_element<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &CompositeLiteralElementNode<'a>,
    location: &Pinned<Location>,
) -> ValueRef<'a> {
    match &node {
        CompositeLiteralElementNode::Expr(expr) => super::visit_single_expr(ctx, expr),
        CompositeLiteralElementNode::Nested(items) => {
            let mut values: Vec<_> = items
                .iter()
                .map(|(_, v)| v)
                .map(|el| visit_array_literal_element(ctx, el, location))
                .filter(|v| !v.is_bottom())
                .collect();

            if values.is_empty() {
                // quicker escape to avoid clones et al. if they're unnecessary
                ValueRef::new_bottom(location.clone())
            } else if values.len() == 1 {
                values.pop().unwrap()
            } else {
                let backtraces: Vec<_> = values.iter().filter_map(ValueRef::backtrace).collect();

                let folded = LabelBacktrace::fold(
                    &backtraces,
                    LabelBacktraceKind::Expression,
                    None,
                    location.clone(),
                );

                ValueRef::from_backtrace_or_bottom_at(folded, || location.clone())
            }
        }
    }
}
