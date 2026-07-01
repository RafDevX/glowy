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

use std::{collections::BTreeSet, path::Path};

use parser::{Location, ParsingError, Span};

use crate::{
    Pinned,
    labels::{Label, LabelBacktrace},
    taint::SinkDescriptor,
};

/// Represents an issue arising from Glowy analysis.
///
/// This struct describes a specific problem that has been identified by
/// Glowy, particularly during its [`crate::Analyzer::analyze`] procedure.
/// Error information is presented in a flexible manner so that the application
/// can decide how to react and choose what details to display.
#[derive(Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
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
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum AnalysisErrorKind<'a> {
    /// Go source code parsing failure.
    ///
    /// This encapsulates a [`parser::ParsingError`], which provides more
    /// information, including through [`ParsingDiagnostics::diagnostics`][PDd].
    ///
    /// [PDd]: crate::ParsingDiagnostics::diagnostics
    Parsing(ParsingError<'a>),

    /// Reuse of virtual file path.
    ///
    /// The file in question was registered multiple times with the Glowy
    /// analyzer, potentially with distinct content.
    DuplicateVirtualFilePath,
    /// Attempt to conduct analysis without specifying any Go source code files.
    ///
    /// Analysis without input trivially resolves to [`Ok`], so there is no need
    /// to invoke the analyzer and thus this likely represents a bug in the
    /// consumer code. This error is reported instead to explicitly bring
    /// attention to this problem so that it may be assessed and fixed (for
    /// example, by adding file registration calls via
    /// [`Analyzer::add_file`](crate::Analyzer::add_file) or equivalent).
    ///
    /// The file path associated with this error is irrelevant and should be
    /// ignored.
    NoRegisteredFiles,
    /// Free build-tag dimensions exceeds the configured limit.
    ///
    /// The analyzer enumerates `2^N` permutations of mentioned build tags,
    /// which becomes impractical beyond a small `N`. When the corpus mentions
    /// more dimensions than the configured value for
    /// `max_build_tag_dimensions`, the analysis is aborted so the invoker can
    /// decide whether to raise the cap and retry or to refine the corpus.
    ///
    /// The file path associated with this error is irrelevant and should be
    /// ignored.
    TooManyBuildTagDimensions {
        /// Configured maximum that was exceeded.
        limit: usize,
        /// All mentioned tag names, from `//go:build` constraints or filenames.
        found: BTreeSet<&'a str>,
    },

    /// Unrecognized directive specified for Glowy annotation.
    ///
    /// A correctly-formatted Glowy annotation includes a directive that is not
    /// known to this analyzer and thus was ignored.
    UnknownAnnotationDirective {
        /// The unrecognized directive in question.
        directive: &'a str,
        /// The offending annotation's location.
        location: Location,
    },
    /// Illegal Glowy declassification annotation with Bottom label.
    ///
    /// Glowy interprets declassification as subtraction, not absolute
    /// overwriting, meaning that declassification of Bottom (i.e., { }) is
    /// meaningless. This error probably indicates an incorrect usage of the
    /// declassification feature, hence it being reported as an error for
    /// enhanced clarity.
    ///
    /// This error is reported not only for invalid direct declassification
    /// annotations, but also for invalid deferred declassification as declared
    /// by an analogously illegal sanitizer annotation with Bottom label.
    InvalidDeclassificationSemantics {
        /// Whether the error stems from direct (vs. deferred) declassification.
        direct: bool,
        /// The offending annotation's location.
        location: Location,
    },

    /// Insecure value passed into security sink.
    ///
    /// A value with incompatible label was fed into a sink without abiding the
    /// defined security policy.
    InsecureFlow {
        /// The sink that the unauthorized information flowed into.
        sink: SinkDescriptor<'a>,
        /// The incompatible label backtrace of the value in question.
        backtrace: LabelBacktrace<'a>,
    },
    /// Expression with differing label from declared expectation.
    ///
    /// A value's calculated label does not match an assertion described in the
    /// defined security policy.
    FalseAssertion {
        /// The expected label defined by the assertion.
        expected: Label<'a>,
        /// The real (incompatible) label backtrace calculated for the value.
        found: Option<LabelBacktrace<'a>>,
        /// The false assertion's location.
        location: Location,
    },

    /// Declared package name different from expectation.
    ///
    /// A Go file's package clause defines a package name different from
    /// what was already declared by another file within the same package.
    /// This file is thus skipped from further analysis.
    DistinctPackageName {
        /// The previously declared package name.
        previous: Pinned<'a, Span<'a>>,
        /// The disparate package clause identifier.
        found: Span<'a>,
    },
    /// Import without specified qualifier of unknown package.
    ///
    /// Another package has been imported via a spec in the form `import "path"`
    /// (without an explicit qualifier being defined), but an implicit qualifier
    /// could not be inferred since the package's native declared package name
    /// could not be ascertained from its package clause, since it has not been
    /// analyzed.
    UnresolvableUnqualifiedImport {
        /// The offending import declaration spec's location.
        location: Location,
    },
    /// Illegal reuse of qualifier in import declaration spec.
    ///
    /// The import declaration conflicts with a previous import declaration
    /// within the same file, now overshadowing it, which is not permitted in
    /// Go in any scenario.
    DuplicateImportQualifier {
        /// The offending import declaration spec's location.
        location: Location,
    },
    /// Invalid declaration of existing symbol in the same scope.
    ///
    /// Go only permits redeclarations under very specific circumstances of
    /// multi-variable short-form declarations. Glowy will proceed as if the
    /// declaration was valid, but the resulting analysis may be incorrect.
    IllegalRedeclaration {
        /// The site of the previous declaration with the same name.
        previous: Pinned<'a, Span<'a>>,
        /// The matching identifier causing an illegal attempt at redeclaration.
        found: Span<'a>,
    },
    /// Invalid access of unknown symbol not declared in the current scope.
    ///
    /// This often stems from incorrect operand name expressions referencing
    /// items that do not exist in the scope (or items that do not exist in the
    /// given namespace, in the case of qualified identifiers).
    UnknownSymbol {
        /// The provided identifier that could not be resolved.
        found: Span<'a>,
    },
    /// Invalid reference to unknown qualifier not imported in the current file.
    ///
    /// This means that a symbol is being accessed with the syntax `qual.name`,
    /// but `qual` could not be resolved since the identifier was never
    /// registered via an import declaration spec such as `import qual "path"`.
    UnknownQualifier {
        /// The provided qualifier that could not be resolved.
        found: Span<'a>,
    },
    /// Illegal return statement outside of a function declaration.
    UnexpectedReturn {
        /// Where the extraneous return statement was found.
        location: Location,
    },
    /// Illegal number of return values differs from previous return statement.
    MismatchingReturnCardinality {
        /// The previously found number of returned values.
        expected: usize,
        /// The number of values described by this return statement.
        found: usize,
        /// Where the invalid return statement was found.
        location: Location,
    },
    /// Illegal statement present after a block-terminating statement.
    Unreachable {
        /// Where the offending statement was found.
        location: Location,
    },
    /// Invalid call of an expression that could not be resolved to a function.
    IllegalCallExpression {
        /// Where the unsupported call expression was found.
        location: Location,
    },
    /// Differing number of arguments in function call wrt function arity.
    IncorrectCallCardinality {
        /// The number of parameters declared in the function signature.
        expected: usize,
        /// The (incorrect) number of arguments passed in the function call.
        found: usize,
        /// Where the function call took place.
        location: Location,
    },
    /// Unsupported or unknown type passed to the a built-in function.
    ///
    /// This may be due to a true Go problem (i.e., non-spec-compliant code), or
    /// due to the analyzer not succeeding at understanding the specified type.
    UnexpectedBuiltInArgShape {
        /// Where the offending built-in function call expression was found.
        location: Location,
    },
    /// Incorrect binding declaration spec with mismatching mappings.
    UnevenBindingDeclSpec {
        /// Where the variable declaration spec was found.
        location: Location,
        /// The number of identifiers found.
        left: usize,
        /// The number of expressions or values found.
        right: usize,
    },
    /// Incorrect assignment with mismatching mappings (count L =/= R).
    UnevenAssignment {
        /// Where the assignment was found.
        location: Location,
        /// The number of left-values found.
        left: usize,
        /// The number of expressions found.
        right: usize,
    },
    /// Invalid complex assignment with more than one left-value.
    MultiComplexAssignment {
        /// Where the assignment was found.
        location: Location,
        /// The number of left-values found.
        num: usize,
    },
    /// Illegal or unsupported expression used as an assignment left-value.
    InvalidLeftValue {
        /// Where the violation was found.
        location: Location,
    },
    /// Constant or unchangeable symbol used as an assignment left-value.
    ImmutableLeftValue {
        /// The immutable symbol.
        symbol: Span<'a>,
    },
    /// Illegal or unsupported expression used as base for selection.
    InvalidSelectionBase {
        /// Where the selection was found.
        location: Location,
    },
    /// Illegal or unsupported expression used as base for indexing.
    InvalidIndexingBase {
        /// Where the indexing was found.
        location: Location,
    },
    /// Illegal or unsupported expression used as base for a slicing.
    InvalidSlicingBase {
        /// Where the slicing was found.
        location: Location,
    },
    /// Invalid or unsupported expression used as operand in receive expression.
    InvalidReceiveOperand {
        /// Where the receive expression was found.
        location: Location,
    },
    /// Illegal `go` statement with a non-call expression.
    GoNotCall {
        /// Where the statement was found.
        location: Location,
    },
    /// Illegal `defer` statement with a non-call expression.
    DeferNotCall {
        /// Where the statement was found.
        location: Location,
    },
    /// Invalid or unsupported communications case in `select` statement.
    ///
    /// If specified (i.e., not `default`), a case within a `select` may only
    /// take the form of a send or a receive statement, with any other
    /// morphology resulting in this error due to being illegal Go code.
    IllegalSelectCase {
        /// Where the communications case was found.
        location: Location,
    },
    /// Illegal `fallthrough` statement in unexpected location.
    ///
    /// Fallthrough statements are only permitted as the last statement of an
    /// expression switch clause. Using a fallthrough statement anywhere else
    /// is invalid.
    UnexpectedFallthrough {
        /// Where the statement was found.
        location: Location,
    },
    /// Duplicate field name specified in struct literal expression.
    DuplicateStructFieldName {
        /// The illegal second field name identifier.
        duplicate: Span<'a>,
    },
    /// Usage of an expression with no value when a single-value was expected.
    UnexpectedVoidExpression {
        /// Where the expression was found.
        location: Location,
    },
    /// Usage of a multi-value expression when a single-value was expected.
    UnexpectedMultiValueExpression {
        /// Where the expression was found.
        location: Location,
    },

    /// Unsupported `defer` statement in `init` function.
    ///
    /// This analyzer version does not support `defer` statements in `init`
    /// functions and so just considers the provided function call as executing
    /// immediately (rather than at the end of the current function), which can
    /// have unexpected implications regarding its side-effects.
    ///
    /// Special treatment is given to `init` functions, so they do not allow for
    /// all possible constructs, even if otherwise permitted in normal Go.
    DeferInInitNotDeferred {
        /// Where the statement was found.
        location: Location,
    },
    /// Unsafe assignment of non-portable function value.
    ///
    /// This happens in control-flow-split contexts (such as if a function-typed
    /// variable declared outside an `if` construct is then reassigned inside
    /// it) where the analyzer cannot prove that overwriting is safe and so must
    /// merge the previous value into the new one, but they are not compatible
    /// and body-derived analysis information cannot safely be ported.
    ///
    /// This error indicates that all deferred enforcement checks present in the
    /// previous function value have been discarded (as they could not safely be
    /// absorbed by the new function value), which is unsound and thus
    /// compromises the analysis results.
    ///
    /// As such, the (valid Go) construct must be rejected with prejudice.
    UnsoundFunctionMergingAssignment {
        /// Where the assignment statement was found located.
        location: Location,
    },
}

impl AnalysisErrorKind<'_> {
    /// Returns a general category to which the error kind belongs.
    #[must_use]
    #[inline]
    pub fn category(&self) -> AnalysisErrorCategory {
        match self {
            Self::Parsing(..)
            | Self::DistinctPackageName { .. }
            | Self::UnresolvableUnqualifiedImport { .. }
            | Self::DuplicateImportQualifier { .. }
            | Self::IllegalRedeclaration { .. }
            | Self::UnknownSymbol { .. }
            | Self::UnknownQualifier { .. }
            | Self::UnexpectedReturn { .. }
            | Self::MismatchingReturnCardinality { .. }
            | Self::Unreachable { .. }
            | Self::IllegalCallExpression { .. }
            | Self::IncorrectCallCardinality { .. }
            | Self::UnexpectedBuiltInArgShape { .. }
            | Self::UnevenBindingDeclSpec { .. }
            | Self::UnevenAssignment { .. }
            | Self::MultiComplexAssignment { .. }
            | Self::InvalidLeftValue { .. }
            | Self::ImmutableLeftValue { .. }
            | Self::InvalidSelectionBase { .. }
            | Self::InvalidIndexingBase { .. }
            | Self::InvalidSlicingBase { .. }
            | Self::InvalidReceiveOperand { .. }
            | Self::GoNotCall { .. }
            | Self::DeferNotCall { .. }
            | Self::IllegalSelectCase { .. }
            | Self::UnexpectedFallthrough { .. }
            | Self::DuplicateStructFieldName { .. }
            | Self::UnexpectedVoidExpression { .. }
            | Self::UnexpectedMultiValueExpression { .. } => AnalysisErrorCategory::InvalidGo,

            Self::DeferInInitNotDeferred { .. } | Self::UnsoundFunctionMergingAssignment { .. } => {
                AnalysisErrorCategory::UnsupportedGo
            }

            Self::DuplicateVirtualFilePath | Self::TooManyBuildTagDimensions { .. } => {
                AnalysisErrorCategory::Misconfiguration
            }

            Self::UnknownAnnotationDirective { .. } => AnalysisErrorCategory::UnrecognizedFeature,

            Self::NoRegisteredFiles | Self::InvalidDeclassificationSemantics { .. } => {
                AnalysisErrorCategory::Suspicious
            }

            Self::InsecureFlow { .. } | Self::FalseAssertion { .. } => {
                AnalysisErrorCategory::SecurityPolicyViolation
            }
        }
    }
}

impl<'a> From<ParsingError<'a>> for AnalysisErrorKind<'a> {
    #[inline]
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
#[derive(Debug, Clone, Copy)]
pub enum AnalysisErrorCategory {
    /// Glowy analyzer not configured correctly.
    Misconfiguration,
    /// Attempt to use a Glowy feature not known to this analyzer version.
    UnrecognizedFeature,
    /// Unexpected behavior likely indicative of underlying analyzer misuse.
    Suspicious,
    /// Incorrect or malformed Go construct.
    InvalidGo,
    /// Go construct recognized but not supported by this analyzer version.
    UnsupportedGo,
    /// Security fault or potential vulnerability detected in the program.
    SecurityPolicyViolation,
}
