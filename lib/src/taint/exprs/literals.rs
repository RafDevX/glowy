use std::collections::HashMap;

use parser::{
    Location,
    ast::{
        CompositeLiteralElementListNode, CompositeLiteralElementNode, ExprNode, FieldDeclNode,
        LiteralNode, StructLiteralFieldsNode, TypeNode,
    },
};

use crate::{
    Pinned,
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind},
    taint::{funcs, types},
    values::{BacktraceContainer, CompositeValue, SimpleConstValue, Value, ValueRef},
};

pub fn visit_literal<'a>(ctx: &mut AnalysisContext<'a>, node: &LiteralNode<'a>) -> ValueRef<'a> {
    match node {
        LiteralNode::Int { location, .. }
        | LiteralNode::Float { location, .. }
        | LiteralNode::Rune { location, .. }
        | LiteralNode::String { location, .. } => {
            ValueRef::new_bottom(ctx.pin(location.clone()), None)
        }
        LiteralNode::Function {
            signature,
            body,
            location,
            annotation,
        } => funcs::visit_function_literal(ctx, signature, body, location, annotation.as_deref()),
        LiteralNode::Array {
            values, location, ..
        } => {
            let location = ctx.pin(location.clone());

            let value = Value::Array(visit_integer_keyed_composite_literal(
                ctx,
                values,
                location.clone(),
            ));

            ValueRef::new(value, location, None)
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

            ValueRef::new(value, location, None)
        }
        LiteralNode::Map {
            values, location, ..
        } => {
            let location = ctx.pin(location.clone());

            let value = Value::Map(visit_map_composite_literal(ctx, values, location.clone()));

            ValueRef::new(value, location, None)
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

            ValueRef::new(value, location, ctx.types().resolve(ctx.symtab(), r#type))
        }
        LiteralNode::UnknownComposite {
            r#type,
            values,
            location,
        } => visit_unknown_composite_literal(ctx, r#type, values, location.clone()),
    }
}

// try to figure out what shape to dispatch to
fn visit_unknown_composite_literal<'a>(
    ctx: &mut AnalysisContext<'a>,
    r#type: &TypeNode<'a>,
    values: &CompositeLiteralElementListNode<'a>,
    location: Location,
) -> ValueRef<'a> {
    let location = ctx.pin(location);

    let underlying = types::resolve_named_underlying(ctx, r#type);

    let value = match &underlying {
        Some(TypeNode::Array { .. }) => Value::Array(visit_integer_keyed_composite_literal(
            ctx,
            values,
            location.clone(),
        )),
        Some(TypeNode::Slice { .. }) => Value::Slice(visit_integer_keyed_composite_literal(
            ctx,
            values,
            location.clone(),
        )),
        Some(TypeNode::Map { .. }) => {
            Value::Map(visit_map_composite_literal(ctx, values, location.clone()))
        }
        resolved => {
            // either we know it's a struct (and have its actual definition with
            // field names), or we couldn't resolve it and treat as struct since
            // that is the most general composite shape with explicit keys

            let dispatch_type = resolved.as_ref().unwrap_or(r#type);
            let fields = raw_list_as_struct_fields(values);

            Value::Struct(visit_struct_composite_literal(
                ctx,
                &fields,
                dispatch_type,
                location.clone(),
            ))
        }
    };

    ValueRef::new(value, location, ctx.types().resolve(ctx.symtab(), r#type))
}

// mirrors parser logic
fn raw_list_as_struct_fields<'a>(
    list: &CompositeLiteralElementListNode<'a>,
) -> StructLiteralFieldsNode<'a> {
    if list.iter().any(|(k, _)| k.is_some()) {
        let mut pairs = Vec::with_capacity(list.len());

        for (key, value) in list {
            let Some(ExprNode::Name(id)) = key else {
                // not a valid Go struct literal shape; degrade by handing
                // everything off as an exhaustive list with no key info, so
                // values still contribute to the dyn backtrace
                return StructLiteralFieldsNode::Exhaustive(
                    list.iter().map(|(_, v)| v.clone()).collect(),
                );
            };

            pairs.push((*id, value.clone()));
        }

        StructLiteralFieldsNode::Keyed(pairs)
    } else {
        StructLiteralFieldsNode::Exhaustive(list.iter().map(|(_, v)| v.clone()).collect())
    }
}

fn visit_integer_keyed_composite_literal<'a>(
    ctx: &mut AnalysisContext<'a>,
    values: &CompositeLiteralElementListNode<'a>,
    location: Pinned<'a, Location>,
) -> CompositeValue<'a, u64> {
    let mut map = HashMap::new();
    let mut others = Vec::new();

    // valid Go array/slice composite literals require constant keys, so
    // in the well-formed case every position is known and the final length is
    // `next_default_key`. we only forfeit that hint if we hit the defensive
    // "non-const key" branch below, where the true length becomes ambiguous
    let mut known_length = true;

    let mut next_default_key = 0;
    for (opt_key, el) in values {
        let value = visit_array_literal_element(ctx, el, &location);

        if is_prunable(&value) {
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

            known_length = false;
            others.push(value);
        }
    }

    let known_len = known_length.then_some(next_default_key);

    CompositeValue::new(map, others, location, known_len)
}

fn visit_map_composite_literal<'a>(
    ctx: &mut AnalysisContext<'a>,
    values: &CompositeLiteralElementListNode<'a>,
    location: Pinned<'a, Location>,
) -> CompositeValue<'a, SimpleConstValue> {
    let mut map = HashMap::new();
    let mut others = Vec::new();

    for (opt_key, el) in values {
        let value = visit_array_literal_element(ctx, el, &location);

        if is_prunable(&value) {
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

    CompositeValue::new(map, others, location, None)
}

fn visit_struct_composite_literal<'a>(
    ctx: &mut AnalysisContext<'a>,
    fields: &StructLiteralFieldsNode<'a>,
    r#type: &TypeNode<'a>,
    location: Pinned<'a, Location>,
) -> CompositeValue<'a, String> {
    let mut map = HashMap::new();
    let mut others = Vec::new();

    match fields {
        StructLiteralFieldsNode::Keyed(entries) => {
            for (field_name, element) in entries {
                let value = visit_array_literal_element(ctx, element, &location);

                if is_prunable(&value) {
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
                let mut candidate = Some(Vec::new());

                for field in type_fields {
                    match field {
                        FieldDeclNode::Explicit(explicit) if let Some(c) = &mut candidate => {
                            c.extend(explicit.ids.iter().map(Option::as_ref));
                        }
                        FieldDeclNode::Explicit(_) => {}
                        FieldDeclNode::Embedded(_) => {
                            candidate = None;
                            break;
                        }
                    }
                }

                candidate.filter(|c| c.len() == entries.len())
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

    CompositeValue::new(map, others, location, None)
}

fn visit_array_literal_element<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &CompositeLiteralElementNode<'a>,
    location: &Pinned<'a, Location>,
) -> ValueRef<'a> {
    match &node {
        CompositeLiteralElementNode::Expr(expr) => super::visit_single_expr(ctx, expr),
        CompositeLiteralElementNode::Nested { elements, .. } => {
            let mut values: Vec<_> = elements
                .iter()
                .map(|(_, v)| v)
                .map(|el| visit_array_literal_element(ctx, el, location))
                .filter(|v| !is_prunable(v))
                .collect();

            if values.is_empty() {
                // quicker escape to avoid clones et al. if they're unnecessary
                ValueRef::new_bottom(location.clone(), None)
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

fn is_prunable(value: &ValueRef<'_>) -> bool {
    // we don't need to bloat the HashMap with Simple values that just hold None
    // backtraces, since that's equivalent to not storing the value at all.
    // however, any shape-carrying value (e.g. Channel or Slice) must be
    // preserved even when empty so downstream shape-sensitive operations still
    // recognize them and shape information propagation actually succeeds
    value.is_simple() && value.is_bottom()
}
