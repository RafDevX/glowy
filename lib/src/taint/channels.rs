use std::{borrow::Cow, cell::Cell};

use glowy_go_parser::{
    Location,
    ast::{ExprNode, SendNode},
};

pub use self::selects::visit_select;
use super::exprs;
use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    policy::{SinkDescriptor, SinkKind},
    taint::{annotations, enforcement, mutation::LeftValue},
    values::{BacktraceContainer, ExpandableValue, SelfAwareBacktraceContainer, Value, ValueRef},
};

mod selects;

pub fn visit_receive<'a>(
    ctx: &mut AnalysisContext<'a>,
    operand: &ExprNode<'a>,
    location: &Location,
) -> ValueRef<'a> {
    let pinned = ctx.pin(location.clone());

    // a receive inside a secret-dependent branch is externally observable:
    // any other holder of the same channel can determine that the receive
    // happened by observing subsequent channel state. mutable left-values go
    // through the normal mutation path so closure captures also record the
    // effect; other expressions can update their shared channel object directly.
    if ctx.branch_backtrace().is_some() && operand.root_operand().is_some() {
        let received = Cell::new(None);

        #[expect(
            clippy::shadow_unrelated,
            reason = "Same context, just threaded through a closure"
        )]
        operand.mutate_target(ctx, location, &|ctx, mut target| {
            let result = receive_from_channel(ctx, &mut target, location, &pinned);
            let succeeded = result.is_some();

            received.set(result);

            succeeded.then_some((target, None))
        });

        received
            .into_inner()
            .unwrap_or_else(|| ValueRef::new_bottom(pinned, None))
    } else {
        let mut value = exprs::visit_single_expr(ctx, operand);

        receive_from_channel(ctx, &mut value, location, &pinned)
            .unwrap_or_else(|| ValueRef::new_bottom(pinned, None))
    }
}

fn receive_from_channel<'a>(
    ctx: &mut AnalysisContext<'a>,
    target: &mut ValueRef<'a>,
    location: &Location,
    pinned: &crate::Pinned<'a, Location>,
) -> Option<ValueRef<'a>> {
    let Some(mut channel) = target.as_channel_mut() else {
        ctx.report_error(AnalysisErrorKind::InvalidReceiveOperand {
            location: location.clone(),
        });

        return None;
    };

    if let Some(branch_backtrace) = ctx.branch_backtrace().cloned() {
        channel.record_receive(branch_backtrace, pinned);
    }

    let (primary, success) = channel.receive(pinned);

    Some(ValueRef::new(
        Value::Expandable(ExpandableValue::new(primary, vec![success])),
        pinned.clone(),
        None,
    ))
}

pub fn visit_send<'a>(ctx: &mut AnalysisContext<'a>, node: &SendNode<'a>) {
    // per the Go spec, the channel expression is evaluated before the value
    if node.channel.root_operand().is_some() {
        #[expect(
            clippy::shadow_unrelated,
            reason = "Same context, just threaded through a closure"
        )]
        node.channel
            .mutate_target(ctx, &node.location, &|ctx, mut target| {
                send_through_channel(ctx, node, &mut target);

                Some((target, None))
            });
    } else {
        let mut target = exprs::visit_single_expr(ctx, &node.channel);

        send_through_channel(ctx, node, &mut target);
    }
}

fn send_through_channel<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &SendNode<'a>,
    target: &mut ValueRef<'a>,
) {
    let base = exprs::visit_single_expr(ctx, &node.expr);

    send_through_channel_with(ctx, node, target, &base);
}

fn send_through_channel_with<'a>(
    ctx: &mut AnalysisContext<'a>,
    node: &SendNode<'a>,
    target: &mut ValueRef<'a>,
    base: &ValueRef<'a>,
) {
    let mut explicit_backtrace = None;
    let mut subtract = Label::Bottom;

    if let Some(annotation) = &node.annotation
        && let Some(directive) = annotations::parse_supported_directive(ctx, annotation)
    {
        match directive {
            annotations::SendDirective::Label => {
                explicit_backtrace = LabelBacktrace::new_root(
                    LabelBacktraceKind::ExplicitAnnotation,
                    Label::from_tags(&annotation.tags),
                    None,
                    ctx.pin(node.location.clone()),
                );
            }
            annotations::SendDirective::Revoke => {
                if let Some(label) = annotations::resolve_revocation_label(ctx, annotation) {
                    subtract = label;
                }
            }
            annotations::SendDirective::AllowSink | annotations::SendDirective::DenySink => {
                let sink = SinkDescriptor::new(
                    SinkKind::Send,
                    directive == annotations::SendDirective::AllowSink,
                    &annotation.tags,
                    node.location.clone(), // statement, not annotation
                );

                if let Some(sink) = sink {
                    enforcement::trigger_sink(ctx, Cow::Owned(sink), base.backtrace());
                } else {
                    ctx.report_error(AnalysisErrorKind::InvalidDenySinkSemantics {
                        location: annotation.location.clone(),
                    });
                }
            }
            annotations::SendDirective::Assert => {
                let sequence = Label::sequence_from_tags(&annotation.tags);

                enforcement::trigger_assertion(
                    ctx,
                    &sequence,
                    base.backtrace(),
                    node.location.clone(),
                );
            }
        }
    }

    let pinned = ctx.pin(node.location.clone());

    let mut sent = base.nest_backtrace(
        LabelBacktraceKind::Send,
        None,
        pinned.clone(),
        explicit_backtrace,
    );
    sent.subtract_label(&subtract);

    let branch_backtrace = ctx.branch_backtrace().cloned();

    let Some(mut channel) = target.as_channel_mut() else {
        return;
    };

    channel.send(sent.backtrace(), branch_backtrace, &pinned);
}
