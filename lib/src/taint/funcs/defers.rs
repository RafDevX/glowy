use std::borrow::Cow;

use glowy_go_parser::ast::{CallNode, ExprNode, TypeNode, UnaryOpKind};

use crate::{
    context::AnalysisContext,
    labels::LabelBacktraceKind,
    symbols::SymbolRef,
    taint::{ResolvedCall, mutation},
    types::TypeKind,
    values::{FunctionValue, Mergeable, ValueRef},
};

pub struct DeferredCallReferents<'a> {
    receiver: Option<DeferredReferent<'a>>,
    arguments: Vec<Option<DeferredReferent<'a>>>,
}

impl<'a> DeferredCallReferents<'a> {
    pub fn capture(
        ctx: &AnalysisContext<'a>,
        resolved: &ResolvedCall<'a>,
        node: &CallNode<'a>,
    ) -> Self {
        let func = resolved.callee.as_function();

        let receiver = if func
            .as_deref()
            .is_some_and(FunctionValue::receiver_is_pointer)
            && let ExprNode::Selection(selection) = &*node.func
        {
            DeferredReferent::new(ctx, &selection.base)
        } else {
            None
        };

        let parameter_slots = func
            .as_deref()
            .and_then(FunctionValue::signature)
            .map(super::collect_parameter_slots);

        let arguments = node
            .args
            .iter()
            .zip(&resolved.arg_values)
            .enumerate()
            .map(|(index, (expr, value))| {
                let parameter_type = parameter_slots.as_deref().and_then(|slots| {
                    slots
                        .get(index)
                        .or_else(|| slots.last().filter(|(_, variadic, _)| *variadic))
                        .map(|(_, _, r#type)| *r#type)
                });

                if argument_may_share_mutable_state(value, expr, parameter_type) {
                    DeferredReferent::new(ctx, expr)
                } else {
                    None
                }
            })
            .collect();

        Self {
            receiver,
            arguments,
        }
    }

    pub fn observe(&self, resolved: &mut ResolvedCall<'a>) {
        if let (Some(referent), Some(saved)) = (&self.receiver, &mut resolved.method_receiver_value)
        {
            *saved = referent.observe(saved);
        }

        for (saved, referent) in resolved.arg_values.iter_mut().zip(&self.arguments) {
            if let Some(referent) = referent {
                *saved = referent.observe(saved);
            }
        }
    }
}

fn argument_may_share_mutable_state(
    value: &ValueRef<'_>,
    expr: &ExprNode<'_>,
    parameter_type: Option<&TypeNode<'_>>,
) -> bool {
    let takes_address = matches!(
        expr,
        ExprNode::UnaryOp {
            kind: UnaryOpKind::Address,
            ..
        }
    );

    let value_may_share_mutable_state =
        || value.is_unknown_composite() || value.is_map() || value.is_slice() || value.is_channel();

    let declared_type_may_share_mutable_state = || {
        value
            .declared_type()
            .and_then(|r#type| r#type.underlying())
            .is_some_and(|kind| {
                matches!(
                    kind,
                    TypeKind::Pointer(_) | TypeKind::Map | TypeKind::Slice | TypeKind::Channel
                )
            })
    };

    let parameter_type_may_share_mutable_state = || {
        parameter_type.is_some_and(|r#type| {
            matches!(
                r#type,
                TypeNode::Pointer { .. }
                    | TypeNode::Map { .. }
                    | TypeNode::Slice { .. }
                    | TypeNode::Channel { .. }
            )
        })
    };

    takes_address
        || value_may_share_mutable_state()
        || declared_type_may_share_mutable_state()
        || parameter_type_may_share_mutable_state()
}

/// A root symbol retained without retaining or replaying its operand
/// expression.
///
/// Replaying the expression at function exit would duplicate its side effects,
/// while retaining only the eagerly evaluated [`ValueRef`] would lose later
/// mutations because symbol assignment replaces the root value.
struct DeferredReferent<'a>(SymbolRef<'a>);

impl<'a> DeferredReferent<'a> {
    fn new(ctx: &AnalysisContext<'a>, expr: &ExprNode<'a>) -> Option<Self> {
        let root = mutation::LeftValue::root_operand(expr)?;
        let symbol = ctx.symtab().get_symbol(root.content())?;

        Some(Self(symbol))
    }

    fn observe(&self, saved: &ValueRef<'a>) -> ValueRef<'a> {
        let current = self
            .0
            .borrow()
            .value()
            .get()
            .with_location(saved.location().clone());

        // the root may have been rebound since the defer statement; merging
        // preserves the eagerly saved value while conservatively including
        // mutations that the analyzer cannot distinguish from rebinding
        saved.merge_with(
            &current,
            LabelBacktraceKind::Expression,
            Cow::Borrowed(saved.location()),
        )
    }
}
