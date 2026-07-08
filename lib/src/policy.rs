//! Module for security policy definition and manipulation.
//!
//! Glowy implements enforcement checks that validate a value's propagated taint
//! against a defined security policy, configured in several different ways for
//! the consumer's convenience. This module contains several necessary types and
//! functionality to allow representing (parts of) such a policy.

use std::{collections::HashMap, error, fmt, str::FromStr};

use parser::Location;

use crate::{
    FullPackagePath,
    labels::{Label, OwnedLabel, OwnedLabelCow},
    snapshots::SnapshotAware,
};

/// Structured information representing a declared sink.
///
/// This is a lightweight descriptor capturing the essential details of an
/// information flow sink as declared by the security policy in effect.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SinkDescriptor<'a> {
    /// The type of sink in question.
    pub kind: SinkKind,
    /// Whether this is a confidentiality sink (allow), vs. integrity (deny).
    pub allow: bool,
    /// The sink's declared expected information label.
    pub label: Label<'a>,
    /// Where the sink was found.
    pub location: Location,
}

impl<'a> SinkDescriptor<'a> {
    pub(crate) fn new(
        kind: SinkKind,
        allow: bool,
        tags: &[&'a str],
        location: Location,
    ) -> Option<Self> {
        if !allow && tags.is_empty() {
            // a `deny` sink with Bottom label makes no sense
            return None;
        }

        let label = Label::from_tags(tags);

        Some(Self {
            kind,
            allow,
            label,
            location,
        })
    }

    /// Evaluates whether a given [`Label`] is accepted by the present sink.
    ///
    /// This method implements the core functionality of how sinks are
    /// interpreted by the analyzer, bridging between a defined security policy
    /// and its actual events when applied to a calculated taint label.
    ///
    /// All sinks always accept [`Label::Bottom`], but any other [`Label`] is
    /// only considered valid if:
    /// - it is a [subset of](Label::is_subset_of) or it is [equal](Label::eq)
    ///   to this sink's inherent policy label, for confidentiality (allow)
    ///   sinks --- whitelist enforcement;
    /// - its [intersection](Label::intersect) with this sink's inherent policy
    ///   label is exactly [`Label::Bottom`], for integrity (deny) sinks ---
    ///   blacklist enforcement.
    ///
    /// This is used by enforcement checks to determine whether an insecure
    /// information flow error should be reported (i.e.,
    /// [`AnalysisErrorKind::InsecureFlow`][AEKif]).
    ///
    /// [AEKif]: crate::errors::AnalysisErrorKind::InsecureFlow
    #[must_use]
    #[inline]
    pub fn accepts(&self, label: &Label<'a>) -> bool {
        if label.is_bottom() {
            // Bottom is always accepted; we can skip the more expensive checks
            return true;
        }

        if self.allow {
            // confidentiality sink (allow - whitelist)
            *label <= self.label
        } else {
            // integrity sink (deny - blacklist)
            label.intersect(&self.label).is_bottom()
        }
    }
}

impl SnapshotAware for SinkDescriptor<'_> {
    fn snapshot_aware_eq(&self, other: &Self) -> bool {
        self == other
    }
}

/// Represents a specific type of information flow sinks.
///
/// This is useful to know, for example, to provide more personalized error
/// messages when a sink's information flow invariant is violated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SinkKind {
    /// A variable/constant declaration.
    Declaration,
    /// An assignment to an existing symbol.
    Assignment,
    /// A function call.
    Call,
    /// A deferred sink via a declared function or defined function literal.
    Function,
    /// A send statement.
    Send,
}

// the map's keys are package path + function name (e.g., `(os, Remove)` or
// `(example.com/company-name/proj/sub-package, funcName)`).
pub(crate) type BlanketDirectives = HashMap<String, HashMap<String, Vec<BlanketDirective>>>;

#[derive(Clone, Debug)]
pub(crate) struct BlanketDirective {
    kind: BlanketDirectiveKind,
    label: OwnedLabel,
}

impl BlanketDirective {
    pub(crate) fn new<'c1: 'c2, 'c2>(
        kind: BlanketDirectiveKind,
        label: impl Into<OwnedLabelCow<'c1, 'c2>>,
    ) -> Self {
        Self {
            kind,
            label: label.into().into_owned(),
        }
    }

    pub fn kind(&self) -> BlanketDirectiveKind {
        self.kind
    }

    pub fn label(&self) -> Label<'_> {
        self.label.as_label()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum BlanketDirectiveKind {
    Source,
    AllowSink,
    DenySink,
}

/// Fully-qualified target of a blanket directive.
///
/// A target is primarily identified by a function path, which is composed of a
/// a fully qualified Go package path ([`Self::package_path`]) as well as the
/// name of the function in question ([`Self::function_name`]). For example,
/// `(os, Remove)` or `(example.com/company-name/proj/sub-package, funcName)`
/// are valid function paths for this context.
///
/// In addition, targets may be optionally narrowed down to specific argument
/// positions via the inclusion of a `#N` suffix (zero-indexed). For instance,
/// `os.WriteFile#1` targets only its second argument. Note, however, that any
/// `arg_index` set for a source directive is ignored, since such restriction is
/// only meaningful for enforcement checks.
///
/// # Parsing and Deserializing
///
/// Often, it is simplest to specify a target as a well-formed [`String`]
/// composed of the package path, followed by a `.` and then the function name.
/// This struct implements [`FromStr`] following this specification, and if the
/// `toml-config` Cargo feature is enabled then it is used to support
/// automatically deserializing a structured target from a provided string via
/// `serde`. For example, the string
/// `example.com/company-name/proj/sub-package.funcName` corresponds to a
/// target with defined `package_name` and `function_name`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlanketDirectiveTarget {
    /// Fully-qualified package path.
    pub package_path: FullPackagePath,
    /// Declared name of the function in question.
    pub function_name: String,
}

impl BlanketDirectiveTarget {
    /// Creates a target for every argument of the given function.
    ///
    /// In most cases, it is more convenient to use the existing [`FromStr`]
    /// implementation instead of invoking this method directly (or, if the
    /// `toml-config` Cargo feature is enabled, automatically deserializing
    /// from a string via `serde`).
    #[inline]
    pub fn new(package_path: impl Into<FullPackagePath>, function_name: impl Into<String>) -> Self {
        Self {
            package_path: package_path.into(),
            function_name: function_name.into(),
            arg_index: None,
        }
    }
}

impl fmt::Display for BlanketDirectiveTarget {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.package_path, self.function_name)
    }
}

impl FromStr for BlanketDirectiveTarget {
    type Err = BlanketDirectiveTargetParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // we need to rsplit instead of split because the package path may
        // contain `.`s (e.g., in `example.com`), so we cannot confuse that with
        // a separator if there is an actual separator later on
        let Some((package_path, function_name)) = s.rsplit_once('.') else {
            return Err(BlanketDirectiveTargetParseError::NoPackageFunctionSeparator);
        };

        if package_path.is_empty() {
            return Err(BlanketDirectiveTargetParseError::EmptyPackagePath);
        }

        if function_name.is_empty() {
            return Err(BlanketDirectiveTargetParseError::EmptyFunctionName);
        }

        Ok(Self::new(package_path, function_name))
    }
}

#[cfg(feature = "toml-config")]
impl<'de> serde::Deserialize<'de> for BlanketDirectiveTarget {
    #[inline]
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // first deserialize to string
        let raw_str = <std::borrow::Cow<'_, str>>::deserialize(deserializer)?;

        // then convert from string to target
        raw_str.parse().map_err(serde::de::Error::custom)
    }
}

/// Represents a failure to parse a string into a [`BlanketDirectiveTarget`].
#[derive(Debug)]
pub enum BlanketDirectiveTargetParseError {
    /// No `.` was located separating the package path from the function name.
    NoPackageFunctionSeparator,
    /// The provided package path is empty.
    EmptyPackagePath,
    /// The provided function name is empty.
    EmptyFunctionName,
}

impl fmt::Display for BlanketDirectiveTargetParseError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPackageFunctionSeparator => {
                f.write_str("blanket directive target has no `.` separator")
            }
            Self::EmptyPackagePath => {
                f.write_str("blanket directive target has empty package path")
            }
            Self::EmptyFunctionName => {
                f.write_str("blanket directive target has empty function name")
            }
        }
    }
}

impl error::Error for BlanketDirectiveTargetParseError {}

#[cfg(test)]
mod target_tests {
    use super::*;

    #[test]
    fn parses_bare_function_path() {
        let target: BlanketDirectiveTarget = "os.Remove".parse().unwrap();
        assert_eq!(target, BlanketDirectiveTarget::new("os", "Remove"));
    }

    #[test]
    fn round_trips_through_display() {
        for input in ["os.Remove", "os.WriteFile#1", "example.com/a/b/pkg.Fn"] {
            let target: BlanketDirectiveTarget = input.parse().unwrap();
            assert_eq!(target.to_string(), input);
        }
    }

    #[test]
    fn rejects_no_separator() {
        assert!(matches!(
            "x".parse::<BlanketDirectiveTarget>(),
            Err(BlanketDirectiveTargetParseError::NoPackageFunctionSeparator)
        ));
    }

    #[test]
    fn rejects_empty_pkg_path() {
        assert!(matches!(
            ".func".parse::<BlanketDirectiveTarget>(),
            Err(BlanketDirectiveTargetParseError::EmptyPackagePath)
        ));
    }

    #[test]
    fn rejects_empty_func_name() {
        assert!(matches!(
            "pkg.".parse::<BlanketDirectiveTarget>(),
            Err(BlanketDirectiveTargetParseError::EmptyFunctionName)
        ));
    }
}
