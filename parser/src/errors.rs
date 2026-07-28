use crate::{
    Span,
    lexer::LexingError,
    parser::BuildConstraintParsingError,
    token::{Token, TokenKind},
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ParsingError<'a> {
    Lexing(LexingError<'a>),
    BuildConstraint(BuildConstraintParsingError<'a>),
    UnexpectedTokenKind {
        expected: TokenKind,
        found: Option<Token<'a>>,      // None means EOF
        context: Option<&'static str>, // for error message
    },
    UnexpectedConstruct {
        expected: &'static str,
        found: Option<Token<'a>>, // None means EOF
    },
}

impl<'a> From<LexingError<'a>> for ParsingError<'a> {
    #[inline]
    fn from(err: LexingError<'a>) -> Self {
        Self::Lexing(err)
    }
}

impl<'a> From<BuildConstraintParsingError<'a>> for ParsingError<'a> {
    #[inline]
    fn from(err: BuildConstraintParsingError<'a>) -> Self {
        Self::BuildConstraint(err)
    }
}

/// Structured human-oriented description of an error to be reported.
///
/// This describes key information about an error that occurred during parsing
/// or one of its sub-processes (such as lexing), presenting it in a standard
/// format for consumption and formatting by a higher-level output mechanism
/// during error reporting.
///
/// Instances are intended to be constructed by error objects themselves through
/// the implementation of the [`Diagnostics::diagnostics`] trait method.
/// Consumers can then invoke the same method on any error object implementing
/// the [`Diagnostics`] trait.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ErrorDiagnosticInfo<'a> {
    /// Unique identifier for this error type.
    ///
    /// This is a 4-character [`String`] comprising a 3-digit (0-padded) numeric
    /// identifier, prefixed by a single uppercase letter indicating a relevant
    /// namespace (for example, `L003` might refer to the third of all possible
    /// errors that may occur during Lexing, for an arbitrary but
    /// non-overlapping ordering).
    pub code: String,
    /// Short summary of the error.
    pub overview: String,
    /// Additional information regarding why this is an error.
    pub details: String,
    /// Optional source code file snippet reference where the error was found.
    pub context: Option<Span<'a>>,
}

/// Functionality relating to the structured description of error objects.
///
/// This trait allows error objects to describe themselves in a standard format
/// ([`ErrorDiagnosticInfo`]) so that such structured information can be used in
/// higher-level output mechanisms when reporting those errors.
pub trait Diagnostics<'a> {
    /// Constructs an informative human-oriented record describing this error.
    fn diagnostics(&self) -> ErrorDiagnosticInfo<'a>;
}

impl<'a> Diagnostics<'a> for ParsingError<'a> {
    #[inline]
    fn diagnostics(&self) -> ErrorDiagnosticInfo<'a> {
        macro_rules! s {
            ($lit:expr) => {
                $lit.to_owned()
            };
        }

        match self {
            Self::Lexing(e) => e.diagnostics(),
            Self::BuildConstraint(e) => e.diagnostics(),
            Self::UnexpectedTokenKind {
                expected,
                found,
                context,
            } => ErrorDiagnosticInfo {
                code: s!("P001"),
                overview: if let Some(ctx) = context {
                    format!("unexpected token in {ctx}")
                } else {
                    s!("unexpected token")
                },
                details: format!(
                    "expected a token of kind {:?}, but found {}",
                    expected,
                    found
                        .as_ref()
                        .map_or_else(|| s!("end-of-file"), |t| format!("{:?}", t.kind))
                ),
                context: found.as_ref().map(|t| t.span),
            },
            Self::UnexpectedConstruct { expected, found } => ErrorDiagnosticInfo {
                code: s!("P002"),
                overview: s!("unexpected construct"),
                details: format!(
                    "expected {}, but found {}",
                    expected,
                    found.as_ref().map_or_else(
                        || s!("end-of-file"),
                        |t| format!("a token of kind {:?}", t.kind)
                    )
                ),
                context: found.clone().map(|t| t.span),
            },
        }
    }
}
