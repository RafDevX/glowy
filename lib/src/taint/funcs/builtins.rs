//! Handling of Go Built-in Functions.
//!
//! Built-in functions are treated in a special manner because they have no
//! signature (per spec) and can have special effects. This module contains
//! handling functions for each of them, taking as input either an ordinary
//! `CallNode` representing a normal function call (since they look exactly
//! like normal function calls and so do not actually have to be identified
//! by the parser, just here during analysis), or otherwise another kind of
//! node, specialized and specific to that built-in function (e.g., for the
//! `make(T, ...)` built-in function, a `MakeNode`) given that they are not
//! treated as function calls by the parser, but rather as their own unique
//! kinds of expressions that are then dispatched by the analyzer on visit.

use std::{borrow::Cow, cell::Cell, collections::HashMap};

use parser::ast::{CallNode, ExprNode, MakeNode, TypeNode};

use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    taint::{exprs, mutation::LeftValue, types},
    values::{
        BacktraceContainer, ChannelValue, CompositeValue, CompositeValueAdapter, SimpleConstValue,
        Value, ValueRef,
    },
};

pub fn visit_make<'a>(ctx: &mut AnalysisContext<'a>, node: &MakeNode<'a>) -> ValueRef<'a> {
    // the first argument is any type whose *underlying* type must be a slice,
    // map, or channel. so for `make(SomeNamedType, ...)` we need to traverse
    // the known defined-type/alias indirections to figure out the actual root
    // underlying type (resolution failure ends up on the wildcard arm; sound)
    let resolved = types::resolve_named_underlying(ctx, &node.r#type);

    // result's declared type is the user-written type (a named alias preserves
    // its identity even though we dispatch on its underlying shape below)
    let declared_type = ctx.types().resolve(ctx.symtab(), &node.r#type);

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "We explicitly only support these types (per Go spec)"
    )]
    match resolved.as_ref().unwrap_or(&node.r#type) {
        TypeNode::Slice { .. } => {
            let known_len = node.n.as_deref().and_then(resolve_const_len);

            let n = node
                .n
                .as_ref()
                .map(|expr| exprs::visit_single_expr(ctx, expr));
            let m = node
                .m
                .as_ref()
                .map(|expr| exprs::visit_single_expr(ctx, expr));

            let location = ctx.pin(node.location.clone());

            #[rustfmt::skip]
            let composite = CompositeValue::new(
                HashMap::new(),
                n.into_iter().chain(m),
                location.clone(),
                known_len,
            );

            ValueRef::new(Value::Slice(composite), location, declared_type)
        }
        TypeNode::Map { .. } => {
            if let Some(m) = &node.m {
                ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
                    expected: 2,
                    found: 3,
                    location: node.location.clone(),
                });

                // visit to trigger side effects even though it shouldn't exist
                exprs::visit_single_expr(ctx, m);
            }

            // we assume "initial space for approximately n elements" is not
            // (easily) observable, so n does NOT taint the resulting map.
            // we just visit to trigger side effects
            node.n
                .as_ref()
                .map(|expr| exprs::visit_single_expr(ctx, expr));

            ValueRef::new(
                Value::Map(CompositeValue::empty(None)),
                ctx.pin(node.location.clone()),
                declared_type,
            )
        }
        TypeNode::Channel { .. } => {
            if let Some(m) = &node.m {
                ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
                    expected: 2,
                    found: 3,
                    location: node.location.clone(),
                });

                // visit to trigger side effects even though it shouldn't exist
                exprs::visit_single_expr(ctx, m);
            }

            let location = ctx.pin(node.location.clone());

            // buffer size determines when sends block (full buffer => sender
            // waits), and that blocking is observable to any receiver via
            // send/receive timing -- so we seed the channel's inner backtrace
            // with n's backtrace, ensuring everything later received from
            // this channel inherits n's label as a sound over-approximation
            let initial = node
                .n
                .as_ref()
                .and_then(|expr| exprs::get_expr_backtrace(ctx, expr));

            ValueRef::new(
                Value::Channel(ChannelValue::new(initial)),
                location,
                declared_type,
            )
        }
        _ => {
            // we don't know what this is, so there's nothing we can do...
            ctx.report_error(AnalysisErrorKind::UnexpectedBuiltInArgShape {
                location: node.location.clone(),
            });

            let n = node
                .n
                .as_ref()
                .and_then(|expr| exprs::get_expr_backtrace(ctx, expr));
            let m = node
                .m
                .as_ref()
                .and_then(|expr| exprs::get_expr_backtrace(ctx, expr));

            let location = ctx.pin(node.location.clone());

            let backtrace = LabelBacktrace::combine_options(
                n,
                m,
                LabelBacktraceKind::Expression,
                Cow::Borrowed(&location),
            );

            ValueRef::from_backtrace_or_bottom_at(backtrace, || location)
                .into_with_declared_type(declared_type)
        }
    }
}

fn resolve_const_len(expr: &ExprNode<'_>) -> Option<u64> {
    match SimpleConstValue::try_resolve_from_expr(expr) {
        Some(SimpleConstValue::Integer(length)) => Some(length),
        _ => None,
    }
}

pub fn visit_append<'a>(ctx: &mut AnalysisContext<'a>, node: &CallNode<'a>) -> ValueRef<'a> {
    // Note: `append` in Go returns a new slice with the appended value, but it
    // does NOT mutate the original slice!

    let location = ctx.pin(node.location.clone());

    if node.args.len() < 2 {
        ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
            expected: 2,
            found: node.args.len(),
            location: node.location.clone(),
        });

        return ValueRef::new_bottom(location, None);
    }

    let original = node.args.first().unwrap(); // already checked length
    let original = exprs::visit_single_expr(ctx, original);
    let mut result = original.clone_inner(); // don't mutate original

    let Some(mut slice) = result.as_slice_mut() else {
        ctx.report_error(AnalysisErrorKind::UnexpectedBuiltInArgShape {
            location: node.location.clone(),
        });

        return ValueRef::new_bottom(location, None);
    };

    if node.variadic {
        // argument is another slice (or a string)
        let [_, other] = node.args.as_slice() else {
            // too many arguments
            ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
                expected: 2,
                found: node.args.len(),
                location: node.location.clone(),
            });

            return ValueRef::new_bottom(location, None);
        };

        let src_value = exprs::visit_single_expr(ctx, other);

        // we need to clone this since we cannot hold a reference to both a
        // ValueRef and its CompositeValue at the same time
        let src_slice = src_value.as_complex_sliceable().as_deref().cloned();

        slice.extend(src_slice, &src_value, location);
    } else {
        // multiple arguments corresponding to individual elements
        for el in node.args.iter().skip(1) {
            let value = exprs::visit_single_expr(ctx, el);

            slice.push(value, || location.clone());
        }
    }

    drop(slice);

    result
}

pub fn visit_copy<'a>(ctx: &mut AnalysisContext<'a>, node: &CallNode<'a>) -> ValueRef<'a> {
    // Note: `copy` in Go mutates the destination slice and returns the number
    // of elements copied, which is min(len(src), len(dst)). This means dst's
    // label must always be raised to the maximum of src and we cannot do
    // anything fancy with const, since all elements matter to the length.
    // Also: some parts of the destination slice might not be overwritten, so we
    // need to remember its backtrace too.

    let location = ctx.pin(node.location.clone());

    let [dst_expr, src_expr] = node.args.as_slice() else {
        ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
            expected: 2,
            found: node.args.len(),
            location: node.location.clone(),
        });

        return ValueRef::new_bottom(location, None);
    };

    let src = exprs::visit_single_expr(ctx, src_expr);

    // captured from inside the transformer so we can build `copy`'s return
    // value (the tainted element count) after the mutation completes
    let combined = Cell::new(None);

    #[expect(
        clippy::shadow_unrelated,
        reason = "Same context, just threaded through the transformer"
    )]
    dst_expr.assign_with(
        ctx,
        LabelBacktraceKind::SliceCopy,
        &node.location,
        &|ctx, mut dst| {
            combined.set(LabelBacktrace::combine_options(
                dst.backtrace(),
                src.backtrace(),
                LabelBacktraceKind::Expression,
                Cow::Borrowed(&location),
            ));

            let Some(mut slice) = dst.as_slice_mut() else {
                ctx.report_error(AnalysisErrorKind::UnexpectedBuiltInArgShape {
                    location: node.location.clone(),
                });

                return None; // abort mutation
            };

            slice.clear(); // we don't want const info anymore
            slice.set_dyn(&src, location.clone());

            drop(slice);

            Some(dst)
        },
    );

    // `copy`'s return value is the number of elements copied, which is tainted
    ValueRef::from_backtrace_or_bottom_at(combined.into_inner(), || location)
}

pub fn visit_clear<'a>(ctx: &mut AnalysisContext<'a>, node: &CallNode<'a>) {
    // `clear` has different behavior depending on whether its argument is a map
    // or a slice. For maps, the result is independent of the original value, so
    // we can just clear the backtrace completely. However, for slices, the
    // slice length remains unchanged (information leak), so we must keep the
    // existing backtrace - just that all consts become dyns.

    // Note: `clear` has no return value.

    let [arg] = node.args.as_slice() else {
        ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
            expected: 1,
            found: node.args.len(),
            location: node.location.clone(),
        });

        return;
    };

    let location = ctx.pin(node.location.clone());

    #[expect(
        clippy::shadow_unrelated,
        reason = "Same context, just threaded through the transformer"
    )]
    arg.assign_with(
        ctx,
        LabelBacktraceKind::CollectionClear,
        &node.location,
        &|ctx, mut current| {
            if current.is_map() {
                // overwrite to bottom
                return Some(ValueRef::new_bottom(location.clone(), None));
            }

            let backtrace = current.backtrace_at_location(location.clone());

            let Some(mut slice) = current.as_slice_mut() else {
                ctx.report_error(AnalysisErrorKind::UnexpectedBuiltInArgShape {
                    location: node.location.clone(),
                });

                return None; // abort mutation
            };

            slice.clear();

            let backtrace_value = ValueRef::from_backtrace_or_bottom_at(
                backtrace, // current value's aggregate backtrace
                || location.clone(),
            );

            slice.set_dyn(&backtrace_value, location.clone());

            drop(slice);

            Some(current)
        },
    );
}

pub fn visit_close<'a>(ctx: &mut AnalysisContext<'a>, node: &CallNode<'a>) {
    // close doesn't actually do anything except if there's a branch backtrace
    // set, so we assign to None to essentially mix in the branch backtrace

    // Note: `clear` has no return value.

    let [arg] = node.args.as_slice() else {
        ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
            expected: 1,
            found: node.args.len(),
            location: node.location.clone(),
        });

        return;
    };

    let location = ctx.pin(node.location.clone());

    arg.assign(
        ctx,
        LabelBacktraceKind::ChannelClose,
        ValueRef::new_bottom(location, None),
        false, // don't want to overwrite
        None,
        &Label::Bottom,
        &node.location,
    );
}

pub fn visit_delete<'a>(ctx: &mut AnalysisContext<'a>, node: &CallNode<'a>) {
    // we essentially treat delete as `m[k] = None`

    // Note: `delete` has no return value.

    let [map, key] = node.args.as_slice() else {
        ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
            expected: 2,
            found: node.args.len(),
            location: node.location.clone(),
        });

        return;
    };

    #[expect(
        clippy::shadow_unrelated,
        reason = "Same context, just threaded through the transformer"
    )]
    map.assign_with(
        ctx,
        LabelBacktraceKind::MapElementDelete,
        &node.location,
        &|ctx, mut value| {
            let Some(mut composite) = value.as_map_mut() else {
                ctx.report_error(AnalysisErrorKind::UnexpectedBuiltInArgShape {
                    location: node.location.clone(),
                });

                return None;
            };

            let location = ctx.pin(node.location.clone());

            composite.set_at_key(
                SimpleConstValue::try_resolve_from_expr(key),
                ValueRef::new_bottom(location.clone(), None),
                location,
            );

            drop(composite);

            Some(value)
        },
    );
}
