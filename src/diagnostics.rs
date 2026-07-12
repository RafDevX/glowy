use std::{borrow::Cow, num::NonZeroUsize, path::Path, sync::OnceLock};

use glowy::errors::AnalysisError;

use crate::errors;

// in each direction (N before and N after)
pub static N_CONTEXT_LINES: OnceLock<usize> = OnceLock::new();

pub fn error_to_group<'a>(
    error: &'a AnalysisError<'a>,
    analyzer: &'a glowy::Analyzer,
    strict: bool,
) -> annotate_snippets::Group<'a> {
    let level = errors::error_category_to_level(error.kind.category(), strict);

    let builder = SnippetBuilder::new(analyzer, error.file);

    let info = errors::get_structured_error_info(&error.kind, &builder);

    let help_msg = info
        .help
        .map(|txt| annotate_snippets::Level::HELP.message(txt))
        .map(annotate_snippets::Element::from);

    let elements = collapse_snippets(info.snippets)
        .into_iter()
        .map(annotate_snippets::Snippet::from)
        .map(annotate_snippets::Element::from);

    level
        .primary_title(info.title)
        .id(info.code)
        .id_url(format!(
            "{}/errors/enum.AnalysisErrorKind.html#variant.{}",
            crate::DOCS_ROOT_URL,
            format!("{:?}", error.kind)
                .split(|ch: char| !ch.is_alphabetic())
                .next()
                .unwrap()
        ))
        .elements(elements.chain(help_msg))
}

// Given a vector of elements, if multiple snippets of the same file are
// presented in a row, all annotations are merged into one single snippet
fn collapse_snippets<'a>(snippets: Vec<StructuredSnippet<'a>>) -> Vec<StructuredSnippet<'a>> {
    let mut new = Vec::with_capacity(snippets.len());

    // we don't use `new.last_mut()` because `.extend` needs to take ownership
    // rather than just a mutable reference (since `.annotate` needs `self`);
    // instead, we use this `previous` variable and then commit it later
    let mut previous: Option<StructuredSnippet<'a>> = None;

    for snippet in snippets {
        if let Some(prev) = previous.take() {
            if snippet.path == prev.path {
                previous = Some(prev.extend(snippet.annotations));
            } else {
                new.push(prev); // commit

                previous = Some(snippet);
            }
        } else {
            previous = Some(snippet);
        }
    }

    new.extend(previous);

    new
}

// we use an intermediate representation (strongly typed) to ensure all errors
// have the same fields defined and none is ever forgotten/missed
#[derive(Debug, Clone)]
pub struct StructuredErrorInfo<'a> {
    pub title: Cow<'a, str>,
    pub code: Cow<'a, str>,
    pub snippets: Vec<StructuredSnippet<'a>>,
    pub help: Option<&'a str>,
}

// intermediate representation (vs. Snippet directly) so we can perform some
// minor manipulation before rendering (Snippet does not expose its data)
// [we need this to be able to collapse snippets]
#[derive(Debug, Clone)]
pub struct StructuredSnippet<'a> {
    path: Cow<'a, str>,
    source: Cow<'a, str>,
    annotations: Vec<StructuredAnnotation<'a>>, // deduplicated
}

impl<'a> StructuredSnippet<'a> {
    pub fn new(path: impl Into<Cow<'a, str>>, source: impl Into<Cow<'a, str>>) -> Self {
        Self {
            path: path.into(),
            source: source.into(),
            annotations: vec![],
        }
    }

    pub fn annotate(mut self, annotation: StructuredAnnotation<'a>) -> Self {
        if !self.annotations.contains(&annotation) {
            self.annotations.push(annotation);
        }

        self
    }

    pub fn extend(
        mut self,
        annotations: impl IntoIterator<Item = StructuredAnnotation<'a>>,
    ) -> Self {
        for annotation in annotations {
            self = self.annotate(annotation);
        }

        self
    }
}

impl<'a> From<StructuredSnippet<'a>>
    for annotate_snippets::Snippet<'a, annotate_snippets::Annotation<'a>>
{
    fn from(snippet: StructuredSnippet<'a>) -> Self {
        let context =
            if let Some(n_lines) = N_CONTEXT_LINES.get().copied().and_then(NonZeroUsize::new) {
                // we inject Visible annotations to provide some context
                // surrounding each actual annotation unless N_CONTEXT_LINES = 0

                snippet
                    .annotations
                    .iter()
                    .map(|annotation| {
                        annotate_snippets::AnnotationKind::Visible.span(calc_context_lines(
                            &snippet.source,
                            &annotation.location,
                            n_lines,
                        ))
                    })
                    .collect()
            } else {
                Vec::new() // does not allocate since it has no elements
            };

        annotate_snippets::Snippet::source(snippet.source)
            .path(snippet.path)
            .annotations(
                snippet
                    .annotations
                    .into_iter()
                    .map(Into::into)
                    .chain(context),
            )
    }
}

fn calc_context_lines(
    source: &str,
    location: &glowy::Location,
    n_lines: NonZeroUsize,
) -> glowy::Location {
    let bytes = source.as_bytes();
    let start = location.start.min(bytes.len());

    let context_start = bytes[..start]
        .iter()
        .enumerate()
        .rev()
        .filter(|(_, byte)| **byte == b'\n')
        .map(|(index, _)| index + 1) // advance newline
        .nth(n_lines.into()) // 0th would be where annotation line begins
        .unwrap_or(0);

    let last_annotated_byte = location.end.saturating_sub(1).min(bytes.len());
    // ^^ we use [length - 1] because Range::end is exclusive and the rendering
    // library allows specifying buffer ranges up to [length + 1]

    let context_end = bytes[last_annotated_byte..]
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'\n')
        .map(|(index, _)| last_annotated_byte + index + 1) // advance newline
        .nth(n_lines.into()) // 0th would be where annotation line ends
        .unwrap_or(bytes.len().saturating_add(1));

    context_start..context_end
}

// intermediate representation (vs. Annotation directly) so we can perform some
// minor manipulation before rendering (Annotation does not expose its data)
// [we need this to be able to deduplicate annotations, since no PartialEq impl]
#[derive(PartialEq, Debug, Clone)]
pub struct StructuredAnnotation<'a> {
    kind: annotate_snippets::AnnotationKind,
    location: glowy::Location,
    label: Option<Cow<'a, str>>,
    highlight_source: bool,
}

impl<'a> StructuredAnnotation<'a> {
    pub fn new(kind: annotate_snippets::AnnotationKind, location: glowy::Location) -> Self {
        Self {
            kind,
            location,
            label: None,
            highlight_source: false,
        }
    }

    pub fn primary(location: glowy::Location) -> Self {
        Self::new(annotate_snippets::AnnotationKind::Primary, location)
    }

    pub fn context(location: glowy::Location) -> Self {
        Self::new(annotate_snippets::AnnotationKind::Context, location)
    }

    pub fn label(mut self, label: impl Into<Cow<'a, str>>) -> Self {
        self.label = Some(label.into());

        self
    }
}

impl<'a> From<StructuredAnnotation<'a>> for annotate_snippets::Annotation<'a> {
    fn from(annotation: StructuredAnnotation<'a>) -> Self {
        annotation
            .kind
            .span(annotation.location)
            .label(annotation.label)
            .highlight_source(annotation.highlight_source)
    }
}

pub struct SnippetBuilder<'a> {
    analyzer: &'a glowy::Analyzer,
    home: &'a Path, // default file
}

impl<'a> SnippetBuilder<'a> {
    pub fn new(analyzer: &'a glowy::Analyzer, home: &'a Path) -> Self {
        Self { analyzer, home }
    }

    pub fn home(&self) -> Cow<'_, str> {
        self.home.to_string_lossy()
    }

    pub fn snippet(&self) -> StructuredSnippet<'a> {
        self.snippet_for(self.home)
    }

    pub fn snippet_for(&self, path: &'a Path) -> StructuredSnippet<'a> {
        let source = self
            .analyzer
            .file_contents(path)
            .expect("specified error file not registered");

        StructuredSnippet::new(path.to_string_lossy(), source)
    }

    pub fn eof(&self) -> glowy::Location {
        self.eof_for(self.home)
    }

    // This method only exists because `annotate_snippets::Snippet` does not
    // make its source field public, meaning we cannot calculate EOF without
    // access to the analyzer's file repository.
    // Note that this might return an empty range if the source file is empty.
    pub fn eof_for(&self, path: &'a Path) -> glowy::Location {
        let source = self
            .analyzer
            .file_contents(path)
            .expect("specified error file not registered");

        source.len().saturating_sub(1)..source.len()
    }
}
