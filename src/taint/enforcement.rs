use std::borrow::Cow;

use parser::Location;

use crate::{
    context::AnalysisContext,
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
        ctx.pin(sink.location.clone()),
    );

    let label = found.as_ref().map_or(&Label::Bottom, LabelBacktrace::label);

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
    expected: Cow<Label<'a>>,
    backtrace: Option<LabelBacktrace<'a>>,
    location: Location,
) {
    let found = LabelBacktrace::combine_options(
        backtrace,
        ctx.branch_backtrace().cloned(),
        LabelBacktraceKind::EnforcementAggregation,
        ctx.pin(location.clone()),
    );

    let label = found.as_ref().map_or(&Label::Bottom, LabelBacktrace::label);

    if *label == *expected {
        // all good! value's label matches the assertion
        return;
    }

    ctx.report_error(AnalysisErrorKind::FalseAssertion {
        expected: expected.into_owned(),
        found,
        location,
    });
}
