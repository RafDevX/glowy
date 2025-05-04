//! Module for analysis error handling.
//!
//! Glowy centralizes all potential problems by always representing them with
//! an instance of [`AnalysisError`], which acts as an "envelope" of sorts
//! containing metainformation about what happened where (such as
//! [`AnalysisError::file`]).
//!
//! Furthermore, [`AnalysisError::kind`] always contains an instance of
//! [`AnalysisErrorKind`] with detailed information on what is being reported,
//! which library users can match on to capture the specific variant of error
//! kind.
//!
//! Finally, [`AnalysisErrorKind::category`] indicates a specific
//! [`AnalysisErrorCategory`] corresponding to the error, which may help guide
//! how the application should proceed (or whether any other results should be
//! considered).
//!
//! See their respective documentation for more details.

use std::path::Path;

use parser::ParsingError;

/// Represents an issue arising from Glowy analysis.
///
/// This struct describes a specific problem that has been identified by
/// Glowy, particularly during its [`crate::Analyzer::analyze`] procedure.
/// Error information is presented in a flexible manner so that the application
/// can decide how to react and choose what details to display.
#[derive(Debug)]
pub struct AnalysisError<'a> {
    /// Go source file during the analysis of which the error was reported.
    ///
    /// This is always a rooted path in connection with the Go module base, such
    /// as `/main.go` or `/auth/oidc.go`, and does not (necessarily) correspond
    /// to any real path on disk.
    pub file: &'a Path,
    /// The type of error that was reported.
    ///
    /// This includes context-specific details of what went wrong, for each
    /// variant.
    pub kind: AnalysisErrorKind<'a>,
}

/// Represents concrete details for a Glowy-identified problem.
///
/// The specific variant of this enum pinpoints what the issue is, with
/// associated fields then describing contextual information. The
/// [`AnalysisErrorKind::category`] method provides a generic overview of the
/// root cause, if a more coarse level of granularity is desired for matching.
#[derive(Debug)]
pub enum AnalysisErrorKind<'a> {
    /// Go source code parsing failure.
    ///
    /// This encapsulates a [`parser::ParsingError`], which provides more
    /// information, including through [`parser::Diagnostics::diagnostics`].
    Parsing(ParsingError<'a>),

    /// Reuse of virtual file path.
    ///
    /// The file in question was registered multiple times with the Glowy
    /// analyzer, potentially with distinct content.
    DuplicateVirtualFilePath,
}

impl<'a> AnalysisErrorKind<'a> {
    /// Returns a general category to which the error kind belongs.
    pub fn category(&self) -> AnalysisErrorCategory {
        match self {
            Self::Parsing(..) => AnalysisErrorCategory::InvalidGo,
            Self::DuplicateVirtualFilePath => AnalysisErrorCategory::Misconfiguration,
        }
    }
}

impl<'a> From<ParsingError<'a>> for AnalysisErrorKind<'a> {
    fn from(err: ParsingError<'a>) -> Self {
        Self::Parsing(err)
    }
}

/// Represents a general group of analysis errors.
///
/// This is useful, for example, when applications need to determine how to
/// proceed (or what merit to assign to a given set of results) depending on
/// the high-level semantic associated with an error, without needing to delve
/// into what in specific happened.
#[derive(Debug)]
pub enum AnalysisErrorCategory {
    /// Glowy analyzer not configured correctly.
    Misconfiguration,
    /// Incorrect or malformed Go construct.
    InvalidGo,
    /// Security fault or potential vulnerability detected in the program.
    SecurityPolicyViolation,
}
