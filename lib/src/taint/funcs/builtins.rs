//! Handling of Go Built-in Functions
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

use std::collections::HashMap;

use parser::ast::{CallNode, MakeNode, TypeNode};

use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind},
    taint::{exprs, mutation::LeftValue},
    values::{
        BacktraceContainer, CompositeValue, SelfAwareBacktraceContainer, SimpleConstValue, Value,
        ValueRef,
    },
};

pub fn visit_make<'a>(ctx: &mut AnalysisContext<'a>, node: &MakeNode<'a>) -> ValueRef<'a> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "We explicitly only support these types (per Go spec)"
    )]
    match &node.r#type {
        TypeNode::Slice { .. } => {
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
            );

            ValueRef::new(Value::Slice(composite), location)
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

            // TODO: maybe add Value::Channel?

            let location = ctx.pin(node.location.clone());

            if let Some(n) = &node.n {
                exprs::visit_single_expr(ctx, n).with_location(location)
            } else {
                ValueRef::new_bottom(location)
            }
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
                location.clone(),
            );

            ValueRef::from_backtrace_or_bottom_at(backtrace, || location)
        }
    }
}

pub fn visit_append<'a>(ctx: &mut AnalysisContext<'a>, node: &CallNode<'a>) -> ValueRef<'a> {
    // Note: `append` in Go returns a new slice with the appended value, but it
    // does NOT mutate the original slice!

    // TODO: is it possible to infer what is the current slice length, at least
    // in some cases, so we can use const instead of dyn?

    let location = ctx.pin(node.location.clone());

    if node.args.len() < 2 {
        ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
            expected: 2,
            found: node.args.len(),
            location: node.location.clone(),
        });

        return ValueRef::new_bottom(location);
    }

    let original = node.args.first().unwrap(); // already checked length
    let original = exprs::visit_single_expr(ctx, original);
    let mut result = original.clone_inner(); // don't mutate original

    let Some(mut slice) = result.as_slice_mut() else {
        ctx.report_error(AnalysisErrorKind::UnexpectedBuiltInArgShape {
            location: node.location.clone(),
        });

        return ValueRef::new_bottom(location);
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

            return ValueRef::new_bottom(location);
        };

        let value = exprs::visit_single_expr(ctx, other);

        slice.set_dyn(&value, location);
    } else {
        // multiple arguments corresponding to individual elements
        for el in node.args.iter().skip(1) {
            let value = exprs::visit_single_expr(ctx, el);

            slice.set_dyn(&value, location.clone());
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

        return ValueRef::new_bottom(location);
    };

    let mut dst = exprs::visit_single_expr(ctx, dst_expr);
    let src = exprs::visit_single_expr(ctx, src_expr);

    let combined = LabelBacktrace::combine_options(
        dst.backtrace(),
        src.backtrace(),
        LabelBacktraceKind::Expression,
        location.clone(),
    );

    let Some(mut slice) = dst.as_slice_mut() else {
        ctx.report_error(AnalysisErrorKind::UnexpectedBuiltInArgShape {
            location: node.location.clone(),
        });

        return ValueRef::new_bottom(location);
    };

    slice.clear(); // we don't want const info anymore
    slice.set_dyn(&src, location.clone());

    drop(slice);

    let value = dst.nest_backtrace(
        LabelBacktraceKind::SliceCopy,
        None,
        location.clone(),
        combined.clone(),
    );

    // this is technically wrong and should be fixed because it'll lead to
    // dst_expr being visited twice, which might have unintended side effects,
    // but since left-values can only be very specific expressions (e.g. operand
    // names or indexing) it should be ok, and there isn't an easier way to do
    // this, at least for now the way the code is structured
    dst_expr.assign(
        ctx,
        LabelBacktraceKind::SliceCopy,
        value,
        true,
        None,
        &node.location,
    );

    // return concerns the number of elements copied, which is tainted
    ValueRef::from_backtrace_or_bottom_at(combined, || location)
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

    let mut current = exprs::visit_single_expr(ctx, arg);

    let location = ctx.pin(node.location.clone());

    let new = if current.is_map() {
        // overwrite to bottom
        ValueRef::new_bottom(location)
    } else {
        // ideally we'd do `} else if let Some(mut slice) = ... {` with then
        // another `} else { ctx.report_error(...); return; };` so it would be
        // more clear that the error arises from current not being neither a map
        // nor a slice, but of course doing that would make the borrow checker
        // very upset because current _might_ be used in the else clause before
        // Option<(slice)> from the if-let could be destructured, so we do this
        // (sillier) version as a workaround

        let backtrace = current.backtrace_at_location(location.clone());

        let Some(mut slice) = current.as_slice_mut() else {
            ctx.report_error(AnalysisErrorKind::UnexpectedBuiltInArgShape {
                location: node.location.clone(),
            });

            return;
        };

        slice.clear();

        let backtrace_value = ValueRef::from_backtrace_or_bottom_at(backtrace, || location.clone());

        slice.set_dyn(&backtrace_value, location);

        drop(slice);

        // just because we mutated it doesn't mean the variable has been updated
        // since `current` is really the result of evaluating an expression and
        // so already an independent instance of the value (due to backtrace
        // nesting with access location)
        current
    };

    // see above in `copy`: this is technically wrong because it means arg expr
    // will be visited twice, but it's the best we can do for now
    arg.assign(
        ctx,
        LabelBacktraceKind::CollectionClear,
        new,
        true,
        None,
        &node.location,
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
        ValueRef::new_bottom(location),
        false, // don't want to overwrite
        None,
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

    let mut value = exprs::visit_single_expr(ctx, map);

    if !value.is_map() {
        ctx.report_error(AnalysisErrorKind::UnexpectedBuiltInArgShape {
            location: node.location.clone(),
        });

        return;
    }

    let mut composite = value.as_composite_mut().unwrap(); // already checked

    let location = ctx.pin(node.location.clone());

    composite.set_at_key(
        SimpleConstValue::try_resolve_from_expr(key),
        ValueRef::new_bottom(location.clone()),
        location,
    );

    drop(composite);

    // visiting twice, technically wrong but ok, see `copy` above
    map.assign(
        ctx,
        LabelBacktraceKind::MapElementDelete,
        value,
        true,
        None,
        &node.location,
    );
}
