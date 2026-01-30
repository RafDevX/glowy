use std::borrow::Cow;

use parser::Location;

use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace},
    taint::SinkDescriptor,
};

pub fn trigger_sink<'a>(
    ctx: &mut AnalysisContext<'a>,
    sink: Cow<SinkDescriptor<'a>>,
    backtrace: Option<LabelBacktrace<'a>>,
) {
    let label = backtrace
        .as_ref()
        .map_or(&Label::Bottom, LabelBacktrace::label);

    if *label <= sink.label {
        // all good! value's label is compatible with sink
        return;
    }

    ctx.report_error(AnalysisErrorKind::InsecureFlow {
        sink: sink.into_owned(),
        backtrace: backtrace.expect("insecure backtrace should not be bottom"),
    });
}

pub fn trigger_assertion<'a>(
    ctx: &mut AnalysisContext<'a>,
    expected: Cow<Label<'a>>,
    backtrace: Option<LabelBacktrace<'a>>,
    location: Location,
) {
    let real = backtrace
        .as_ref()
        .map_or(&Label::Bottom, LabelBacktrace::label);

    if *real == *expected {
        // all good! value's label matches the assertion
    }

    ctx.report_error(AnalysisErrorKind::FalseAssertion {
        expected: expected.into_owned(),
        found: backtrace,
        location,
    });
}
