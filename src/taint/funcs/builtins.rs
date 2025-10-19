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
    taint::exprs,
    values::{CompositeValue, Value, ValueRef},
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
        // argument is another slice
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
