use parser::Annotation;
use subenum::subenum;

use crate::{context::AnalysisContext, errors::AnalysisErrorKind, labels::Label};

#[subenum(
    ExprDirective,
    DeclDirective,
    AssignmentDirective,
    SendDirective,
    CallDirective,
    FunctionDirective
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnnotationDirective {
    #[subenum(DeclDirective, AssignmentDirective, SendDirective, FunctionDirective)]
    Label,
    #[subenum(DeclDirective, AssignmentDirective, SendDirective)]
    Declassify,
    #[subenum(FunctionDirective)]
    Sanitizer,
    #[subenum(
        DeclDirective,
        AssignmentDirective,
        SendDirective,
        CallDirective,
        FunctionDirective
    )]
    Sink,
    #[subenum(
        ExprDirective,
        DeclDirective,
        AssignmentDirective,
        CallDirective,
        SendDirective
    )]
    Assert,
}

impl AnnotationDirective {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "label" => Some(Self::Label),
            "declassify" => Some(Self::Declassify),
            "sanitizer" => Some(Self::Sanitizer),
            "sink" => Some(Self::Sink),
            "assert" => Some(Self::Assert),
            _ => None,
        }
    }
}

pub fn parse_supported_directive<'a, S: TryFrom<AnnotationDirective>>(
    ctx: &mut AnalysisContext<'a>,
    annotation: &Annotation<'a>,
) -> Option<S> {
    let directive = AnnotationDirective::parse(annotation.directive)
        .map(S::try_from)
        .and_then(Result::ok);

    if let Some(directive) = directive {
        Some(directive)
    } else {
        ctx.report_error(AnalysisErrorKind::UnknownAnnotationDirective {
            directive: annotation.directive,
            location: annotation.location.clone(),
        });

        None
    }
}

pub fn resolve_declassification_label<'a>(
    ctx: &mut AnalysisContext<'a>,
    annotation: &Annotation<'a>,
    direct: bool,
) -> Option<Label<'a>> {
    if annotation.tags.is_empty() {
        ctx.report_error(AnalysisErrorKind::InvalidDeclassificationSemantics {
            direct,
            location: annotation.location.clone(),
        });

        None
    } else {
        Some(Label::from_tags(&annotation.tags))
    }
}
