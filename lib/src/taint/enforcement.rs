use std::borrow::Cow;

use parser::Location;

use crate::{
    context::{AnalysisContext, DeferredEnforcementCheck},
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
    taint::SinkDescriptor,
};

pub fn trigger_sink<'a>(
    ctx: &mut AnalysisContext<'a>,
    sink: Cow<SinkDescriptor<'a>>,
    backtrace: Option<LabelBacktrace<'a>>,
) {
    let found = LabelBacktrace::combine_options(
        backtrace,
        ctx.branch_backtrace().cloned(),
        LabelBacktraceKind::EnforcementAggregation,
        Cow::Owned(ctx.pin(sink.location.clone())),
    );

    let label = found.as_ref().map_or(&Label::Bottom, LabelBacktrace::label);

    if label.has_any_synthetic() {
        // we cannot evaluate this sink at this point in time, since the passed
        // label depends on at least one synthetic tag which will only be
        // resolved at call-time
        ctx.defer_enforcement_check(DeferredEnforcementCheck::Sink {
            sink: sink.into_owned(),
            found: found.unwrap(), // safe, as label not Bottom (has synthetic)
            file: ctx.current_file().unwrap(),
        });

        return;
    }

    if *label <= sink.label {
        // all good! value's label is compatible with sink
        return;
    }

    ctx.report_error(AnalysisErrorKind::InsecureFlow {
        sink: sink.into_owned(),
        backtrace: found.unwrap(), // safe, guaranteed by comparison above
    });
}

pub fn trigger_assertion<'a>(
    ctx: &mut AnalysisContext<'a>,
    expected_sequence: &[Label<'a>],
    backtrace: Option<LabelBacktrace<'a>>,
    location: Location,
) {
    let found = LabelBacktrace::combine_options(
        backtrace,
        ctx.branch_backtrace().cloned(),
        LabelBacktraceKind::EnforcementAggregation,
        Cow::Owned(ctx.pin(location.clone())),
    );

    let label = found.as_ref().map_or(&Label::Bottom, LabelBacktrace::label);

    if label.has_any_synthetic() {
        // we cannot evaluate this check at this point in time, since the passed
        // label depends on at least one synthetic tag which will only be
        // resolved at call-time
        ctx.defer_enforcement_check(DeferredEnforcementCheck::Assertion {
            expected_sequence: Vec::from(expected_sequence),
            found,
            file: ctx.current_file().unwrap(),
            location,
        });

        return;
    }

    let expected_label = expected_sequence.first().unwrap_or(&Label::Bottom);

    if *label == *expected_label {
        // all good! value's label matches the assertion
        return;
    }

    ctx.report_error(AnalysisErrorKind::FalseAssertion {
        expected: expected_label.clone(),
        found,
        location,
    });
}

// returns whether the check triggered or if it must be propagated further
#[must_use]
pub fn try_trigger_deferred_check<'a>(
    ctx: &mut AnalysisContext<'a>,
    check: &DeferredEnforcementCheck<'a>,
    call_index: usize,
) -> bool {
    let bt = match &check {
        DeferredEnforcementCheck::Sink { found, .. } => Some(found),
        DeferredEnforcementCheck::Assertion { found, .. } => found.as_ref(),
    };
    let label = bt.map_or(&Label::Bottom, LabelBacktrace::label);

    if label.has_any_synthetic() {
        return false;
    }

    match check {
        DeferredEnforcementCheck::Sink { sink, .. } if *label <= sink.label => {} // all good
        DeferredEnforcementCheck::Sink { sink, found, file } => {
            ctx.report_error_at(
                file,
                AnalysisErrorKind::InsecureFlow {
                    sink: sink.clone(),
                    backtrace: found.clone(),
                },
            );
        }
        DeferredEnforcementCheck::Assertion {
            expected_sequence,
            found,
            file,
            location,
        } => {
            let expected = expected_sequence
                .get(call_index)
                .or_else(|| expected_sequence.last())
                .unwrap_or(&Label::Bottom);

            if *label == *expected {
                // all good
            } else {
                ctx.report_error_at(
                    file,
                    AnalysisErrorKind::FalseAssertion {
                        expected: expected.clone(),
                        found: found.clone(),
                        location: location.clone(),
                    },
                );
            }
        }
    }

    true
}
