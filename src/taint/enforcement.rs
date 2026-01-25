use parser::Location;

use crate::{
    context::AnalysisContext,
    errors::AnalysisErrorKind,
    labels::{Label, LabelBacktrace},
    taint::SinkDescriptor,
    values::{BacktraceContainer, ValueRef},
};

pub fn trigger_sink<'a>(
    ctx: &mut AnalysisContext<'a>,
    sink: SinkDescriptor<'a>,
    location: &Location,
    value: ValueRef<'a>,
) {
    // FIXME: this location is probably wrong for what we want to report,
    // e.g. we want to highlight a specific argument rather than an entire
    // function call, but we don't have that information here
    let location = ctx.pin(location.clone());

    let backtrace = value.backtrace_at_location(location);

    let label = backtrace
        .as_ref()
        .map_or(&Label::Bottom, LabelBacktrace::label);

    if *label <= sink.label {
        // all good! value's label is compatible with sink
        return;
    }

    ctx.report_error(AnalysisErrorKind::InsecureFlow { sink, backtrace });
}
