use std::collections::HashMap;

use parser::ast::{MakeNode, TypeNode};

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
            ctx.report_error(AnalysisErrorKind::UnsupportedMakeExpression {
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
