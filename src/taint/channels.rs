use std::borrow::Cow;

use parser::{
    Location,
    ast::{ExprNode, SendNode},
};

use super::exprs;
use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    taint::{SinkDescriptor, SinkKind, enforcement, explicit::LeftValue},
    values::{SelfAwareBacktraceContainer, ValueRef},
};

pub fn visit_receive<'a>(
    ctx: &mut AnalysisContext<'a>,
    operand: &ExprNode<'a>,
    location: &Location,
) -> ValueRef<'a> {
    // TODO: must update channel's label to match branch label, because
    // otherwise "has a value been read" or "has the channel been depleted" can
    // be used to exfiltrate information

    exprs::visit_single_expr(ctx, operand).nest_backtrace(
        LabelBacktraceKind::Receive,
        None,
        ctx.pin(location.clone()),
        vec![],
    )
}

pub fn visit_send<'a>(ctx: &mut AnalysisContext<'a>, node: &SendNode<'a>) {
    let mut explicit_backtrace = None;

    if let Some(annotation) = &node.annotation {
        match annotation.directive {
            "label" => {
                explicit_backtrace = Some(LabelBacktrace::new_root(
                    LabelBacktraceKind::ExplicitAnnotation,
                    Label::from_tags(&annotation.tags),
                    None,
                    ctx.pin(node.location.clone()),
                ));
            }
            "sink" => {
                let sink = SinkDescriptor::new(SinkKind::Send, &annotation.tags);

                let backtrace = exprs::get_expr_backtrace(ctx, &node.expr);

                enforcement::trigger_sink(ctx, Cow::Owned(sink), backtrace);
            }
            _ => ctx.report_error(AnalysisErrorKind::UnknownAnnotationDirective {
                directive: annotation.directive.to_owned(),
                location: annotation.location.clone(),
            }),
        }
    }

    let base = exprs::visit_single_expr(ctx, &node.expr);

    // we take send as syntactic sugar for a complex assignment
    node.channel.assign(
        ctx,
        LabelBacktraceKind::Send,
        base,
        false, // don't overwrite ever
        explicit_backtrace.as_ref(),
        &node.location,
    );
}
