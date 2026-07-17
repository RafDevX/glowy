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
    labels::{LabelBacktrace, LabelBacktraceKind},
    taint::{exprs, mutation::LeftValue, types},
    values::{
        BacktraceContainer, ChannelValue, CompositeValue, CompositeValueAdapter, SimpleConstValue,
        Value, ValueRef,
    },
};

pub fn visit_make<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &MakeNode<'a>,
    arg_consts: &mut [Option<SimpleConstValue>],
) -> ValueRef<'a> {
    // the first argument is any type whose *underlying* type must be a slice,
    // map, or channel. so for `make(SomeNamedType, ...)` we need to traverse
    // the known defined-type/alias indirections to figure out the actual root
    // underlying type (resolution failure ends up on the wildcard arm; sound)
    let resolved = types::resolve_named_underlying(ctx, &node.r#type);

    // result's declared type is the user-written type (a named alias preserves
    // its identity even though we dispatch on its underlying shape below)
    let declared_type = {
        let (types, symtab) = ctx.types_mut_with_symtab();

        types.resolve(symtab, &node.r#type)
    };

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "We explicitly only support these types (per Go spec)"
    )]
    match resolved.as_ref().unwrap_or(&node.r#type) {
        TypeNode::Slice { .. } => {
            let known_len = node
                .n
                .as_deref()
                .and_then(|expr| resolve_const_len(ctx, expr, arg_consts));

            let n = node
                .n
                .as_ref()
                .map(|expr| exprs::visit_single_expr(ctx, expr));

            let m = node.m.as_ref().map(|expr| {
                capture_arg_const(ctx, expr, arg_consts, 2);

                exprs::visit_single_expr(ctx, expr)
            });

            let location = ctx.pin(node.location.clone());

            #[rustfmt::skip]
            let composite = CompositeValue::new(
                HashMap::new(),
                n.into_iter().chain(m),
                None,
                known_len,
                location.clone(),
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
                capture_arg_const(ctx, m, arg_consts, 2);
                exprs::visit_single_expr(ctx, m);
            }

            // we assume "initial space for approximately n elements" is not
            // (easily) observable, so n does NOT taint the resulting map.
            // we just visit to trigger side effects
            node.n.as_ref().map(|expr| {
                capture_arg_const(ctx, expr, arg_consts, 1);

                exprs::visit_single_expr(ctx, expr)
            });

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
                capture_arg_const(ctx, m, arg_consts, 2);
                exprs::visit_single_expr(ctx, m);
            }

            let location = ctx.pin(node.location.clone());

            // buffer size determines when sends block (full buffer => sender
            // waits), and that blocking is observable to any receiver via
            // send/receive timing -- so we seed the channel's inner backtrace
            // with n's backtrace, ensuring everything later received from
            // this channel inherits n's label as a sound over-approximation
            let initial = node.n.as_ref().and_then(|expr| {
                capture_arg_const(ctx, expr, arg_consts, 1);

                exprs::get_expr_backtrace(ctx, expr)
            });

            let channel = ChannelValue::new_allocated(initial, location.clone());

            ValueRef::new(Value::Channel(channel), location, declared_type)
        }
        _ => {
            // we don't know what this is, so there's nothing we can do...
            ctx.report_error(AnalysisErrorKind::UnexpectedBuiltInArgShape {
                location: node.location.clone(),
            });

            let n = node.n.as_ref().and_then(|expr| {
                capture_arg_const(ctx, expr, arg_consts, 1);

                exprs::get_expr_backtrace(ctx, expr)
            });

            let m = node.m.as_ref().and_then(|expr| {
                capture_arg_const(ctx, expr, arg_consts, 2);

                exprs::get_expr_backtrace(ctx, expr)
            });

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

fn resolve_const_len(
    ctx: &AnalysisContext<'_>,
    expr: &ExprNode<'_>,
    arg_consts: &mut [Option<SimpleConstValue>],
) -> Option<u64> {
    match capture_arg_const(ctx, expr, arg_consts, 1) {
        Some(SimpleConstValue::Integer(length)) => Some(*length),
        _ => None,
    }
}

pub fn visit_append<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &CallNode<'a>,
    arg_consts: &mut [Option<SimpleConstValue>],
) -> ValueRef<'a> {
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

    capture_arg_const(ctx, original, arg_consts, 0);

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

        capture_arg_const(ctx, other, arg_consts, 1);
        let src_value = exprs::visit_single_expr(ctx, other);

        // we need to clone this since we cannot hold a reference to both a
        // ValueRef and its CompositeValue at the same time
        let src_slice = src_value.as_complex_sliceable().as_deref().cloned();

        slice.extend(src_slice, &src_value, location);
    } else {
        // multiple arguments corresponding to individual elements
        for (index, el) in node.args.iter().enumerate().skip(1) {
            capture_arg_const(ctx, el, arg_consts, index);

            let value = exprs::visit_single_expr(ctx, el);

            slice.push(value, || location.clone());
        }
    }

    drop(slice);

    result
}

pub fn visit_copy<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &CallNode<'a>,
    arg_consts: &mut [Option<SimpleConstValue>],
) -> ValueRef<'a> {
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

    capture_arg_const(ctx, dst_expr, arg_consts, 0);
    capture_arg_const(ctx, src_expr, arg_consts, 1);

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

pub fn visit_clear<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &CallNode<'a>,
    arg_consts: &mut [Option<SimpleConstValue>],
) {
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

    capture_arg_const(ctx, arg, arg_consts, 0);

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

pub fn visit_close<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &CallNode<'a>,
    arg_consts: &mut [Option<SimpleConstValue>],
) {
    // closing under secret-dependent control is observable through a later
    // receive, so record the current branch backtrace on the shared state.

    // Note: `close` has no return value.

    let [arg] = node.args.as_slice() else {
        ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
            expected: 1,
            found: node.args.len(),
            location: node.location.clone(),
        });

        return;
    };

    capture_arg_const(ctx, arg, arg_consts, 0);

    if arg.root_operand().is_some() {
        #[expect(
            clippy::shadow_unrelated,
            reason = "Same context, just threaded through a closure"
        )]
        arg.mutate_target(ctx, &node.location, &|ctx, mut target| {
            close_channel(ctx, &mut target, &node.location);

            Some((target, None))
        });
    } else {
        let mut target = exprs::visit_single_expr(ctx, arg);

        close_channel(ctx, &mut target, &node.location);
    }
}

fn close_channel<'a>(
    ctx: &AnalysisContext<'a>,
    target: &mut ValueRef<'a>,
    location: &parser::Location,
) {
    let Some(branch_backtrace) = ctx.branch_backtrace().cloned() else {
        return;
    };

    let Some(mut channel) = target.as_channel_mut() else {
        return;
    };

    let pinned = ctx.pin(location.clone());

    channel.close(Some(branch_backtrace), &pinned);
}

pub fn visit_delete<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &CallNode<'a>,
    arg_consts: &mut [Option<SimpleConstValue>],
) {
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

    capture_arg_const(ctx, map, arg_consts, 0);
    capture_arg_const(ctx, key, arg_consts, 1);

    // evaluate before map to trigger side-effects in the correct order
    let (key_backtrace, key_const) = exprs::get_expr_backtrace_and_untainted_const(ctx, key);

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

            // cloning key and key_backtrace is necessary because this closure
            // is an Fn, meaning it could technically execute multiple times
            // (even if it actually does not) -- it cannot be changed to an
            // FnOnce because then it would have to be invoked with ownership,
            // meaning passing a reference to the closure would not be enough,
            // and so instead of the signature being `&dyn Fn` it would have to
            // be `impl FnOnce`, but that would make the LeftValue trait not
            // dyn-compatible, which is not what we want; we also can't just use
            // a `Box<dyn FnOnce>`, since then that would require the 'a in
            // `LeftValue<'a>` to live for 'static, which is not possible
            composite.set_at_key(
                key_const.clone(),
                ValueRef::new_bottom(location.clone(), None),
                key_backtrace.clone(),
                location,
            );

            drop(composite);

            Some(value)
        },
    );
}

pub fn visit_len<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &CallNode<'a>,
    arg_consts: &mut [Option<SimpleConstValue>],
) -> ValueRef<'a> {
    let location = ctx.pin(node.location.clone());

    let [arg] = node.args.as_slice() else {
        ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
            expected: 1,
            found: node.args.len(),
            location: node.location.clone(),
        });

        return ValueRef::new_bottom(location, None);
    };

    capture_arg_const(ctx, arg, arg_consts, 0);
    let value = exprs::visit_single_expr(ctx, arg);

    // check with `is_composite` before casting with `as_composite` to avoid
    // triggering an upgrade, as `len` can also operate on strings and channels
    // and we don't want to mis-upgrade them to an array, especially since the
    // upgrade would be useless to us here (wouldn't have known length anyway)
    let backtrace = if value.is_composite()
        && let Some(composite) = value.as_composite()
    {
        composite.length_backtrace_at_location(location.clone())
    } else {
        value.backtrace()
    };

    ValueRef::from_backtrace_or_bottom_at(backtrace, || location)
}

fn capture_arg_const<'c>(
    ctx: &AnalysisContext<'_>,
    expr: &ExprNode<'_>,
    arg_consts: &'c mut [Option<SimpleConstValue>],
    index: usize,
) -> Option<&'c SimpleConstValue> {
    let slot = arg_consts.get_mut(index)?;

    *slot = exprs::try_resolve_simple_const(ctx, expr);

    slot.as_ref()
}
