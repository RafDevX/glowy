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

use std::{collections::HashMap, iter};

use parser::ast::{AssignmentKind, CallNode, MakeNode, TypeNode};

use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{LabelBacktrace, LabelBacktraceKind},
    taint::{explicit, exprs},
    values::{BacktraceContainer, CompositeValue, SelfAwareBacktraceContainer, Value, ValueRef},
};

pub fn visit_make<'a>(ctx: &mut AnalysisContext<'a>, node: &MakeNode<'a>) -> ValueRef<'a> {
    match &node.r#type {
        TypeNode::Slice { element } => {
            let n = node
                .n
                .as_ref()
                .map(|expr| exprs::visit_single_expr(ctx, expr));
            let m = node
                .m
                .as_ref()
                .map(|expr| exprs::visit_single_expr(ctx, expr));

            let mut composite = CompositeValue::new(
                HashMap::new(),
                n.into_iter().chain(m),
                ctx.pin(node.location.clone()),
            );

            let default = ValueRef::uninitialized_from_type(Some(element));
            if !default.is_simple() {
                composite.set_default_value(default);
            }

            ValueRef::from(Value::Slice(composite))
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

            ValueRef::from(Value::Map(CompositeValue::empty()))
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

            if let Some(n) = &node.n {
                exprs::visit_single_expr(ctx, n)
            } else {
                ValueRef::from(None)
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

            let backtrace = LabelBacktrace::combine_options(
                n,
                m,
                LabelBacktraceKind::Expression,
                ctx.pin(node.location.clone()),
            );

            ValueRef::from(backtrace)
        }
    }
}

pub fn visit_append<'a>(ctx: &mut AnalysisContext<'a>, node: &CallNode<'a>) -> ValueRef<'a> {
    // Note: `append` in Go returns a new slice with the appended value, but it
    // does NOT mutate the original slice!

    // TODO: is it possible to infer what is the current slice length, at least
    // in some cases, so we can use const instead of dyn?

    if node.args.len() < 2 {
        ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
            expected: 2,
            found: node.args.len(),
            location: node.location.clone(),
        });

        return ValueRef::from(None);
    }

    let original = node.args.first().unwrap(); // already checked length
    let original = exprs::visit_single_expr(ctx, original);
    let mut result = original.clone_inner(); // don't mutate original

    let Some(mut slice) = result.as_slice_mut() else {
        ctx.report_error(AnalysisErrorKind::UnexpectedBuiltInArgShape {
            location: node.location.clone(),
        });

        return ValueRef::from(None);
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

            return ValueRef::from(None);
        };

        let value = exprs::visit_single_expr(ctx, other);

        slice.set_dyn(value, ctx.pin(node.location.clone()));
    } else {
        // multiple arguments corresponding to individual elements
        for el in node.args.iter().skip(1) {
            let value = exprs::visit_single_expr(ctx, el);

            slice.set_dyn(value, ctx.pin(node.location.clone()));
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

    let [dst_expr, src_expr] = node.args.as_slice() else {
        ctx.report_error(AnalysisErrorKind::IncorrectCallCardinality {
            expected: 2,
            found: node.args.len(),
            location: node.location.clone(),
        });

        return ValueRef::from(None);
    };

    let dst_location = ctx.pin(exprs::get_expr_location(dst_expr));
    let src_location = ctx.pin(exprs::get_expr_location(src_expr));

    let mut dst = exprs::visit_single_expr(ctx, dst_expr);
    let src = exprs::visit_single_expr(ctx, src_expr);

    let combined = LabelBacktrace::combine_options(
        dst.backtrace_at_location(dst_location),
        src.backtrace_at_location(src_location),
        LabelBacktraceKind::Expression,
        ctx.pin(node.location.clone()),
    );

    let Some(mut slice) = dst.as_slice_mut() else {
        ctx.report_error(AnalysisErrorKind::UnexpectedBuiltInArgShape {
            location: node.location.clone(),
        });

        return ValueRef::from(None);
    };

    slice.clear(); // we don't want const info anymore
    slice.set_dyn(src, ctx.pin(node.location.clone()));

    drop(slice);

    let value = dst.nest_backtrace(
        LabelBacktraceKind::SliceCopy,
        None,
        ctx.pin(node.location.clone()),
        combined.clone(),
    );

    // this is technically wrong and should be fixed because it'll lead to
    // dst_expr being visited twice, which might have unintended side effects,
    // but since left-values can only be very specific expressions (e.g. operand
    // names or indexing) it should be ok, and there isn't an easier way to do
    // this, at least for now the way the code is structured
    explicit::visit_raw_assignment(
        ctx,
        AssignmentKind::Simple,
        iter::once(dst_expr),
        iter::once(value),
        None,
        &node.location,
    );

    // return concerns the number of elements copied, which is tainted
    ValueRef::from(combined)
}
