use std::borrow::Cow;

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
        backtrace,
    });
}
