//! Module for security policy definition and manipulation.
//!
//! Glowy implements enforcement checks that validate a value's propagated taint
//! against a defined security policy, configured in several different ways for
//! the consumer's convenience. This module contains several necessary types and
//! functionality to allow representing (parts of) such a policy.

use std::{collections::HashMap, error, fmt, num::ParseIntError, str::FromStr};

use parser::Location;

use crate::{FullPackagePath, labels::Label, snapshots::SnapshotAware};

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

pub(crate) type BlanketDirectives = HashMap<FullPackagePath, PackageBlanketDirectives>;

#[derive(Default)]
pub(crate) struct PackageBlanketDirectives {
    // top-level package symbols: functions (`os.GetEnv`) & bindings (`os.Args`)
    pub symbols: HashMap<String, Vec<BlanketDirective>>,
    // type-associated members: methods (`DB.Query`) & fields (`Request.Body`)
    pub type_members: HashMap<String, HashMap<String, Vec<BlanketDirective>>>,
}

impl PackageBlanketDirectives {
    pub fn get(&self, type_name: Option<&str>, member_name: &str) -> Option<&[BlanketDirective]> {
        match type_name {
            None => self.symbols.get(member_name).map(Vec::as_slice),
            Some(type_name) => self
                .type_members
                .get(type_name)
                .and_then(|inner| inner.get(member_name))
                .map(Vec::as_slice),
        }
    }

    pub fn push(
        &mut self,
        type_name: Option<String>,
        member_name: String,
        directive: BlanketDirective,
    ) {
        let entry = match type_name {
            None => self.symbols.entry(member_name).or_default(),
            Some(type_name) => self
                .type_members
                .entry(type_name)
                .or_default()
                .entry(member_name)
                .or_default(),
        };

        entry.push(directive);
    }

    pub fn iter(&self) -> impl Iterator<Item = &BlanketDirective> {
        self.symbols.values().flatten().chain(
            self.type_members
                .values()
                .flat_map(HashMap::values)
                .flatten(),
        )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct BlanketDirective {
    kind: BlanketDirectiveKind,
    label: Label<'static>,
    arg_index: Option<usize>,
}

impl BlanketDirective {
    pub(crate) fn new(
        kind: BlanketDirectiveKind,
        arg_index: Option<usize>,
        label: Label<'static>,
    ) -> Self {
        // sources don't have a meaningful notion of "this arg only"
        let arg_index = match kind {
            BlanketDirectiveKind::Source => None,
            BlanketDirectiveKind::AllowSink | BlanketDirectiveKind::DenySink => arg_index,
        };

        Self {
            kind,
            label,
            arg_index,
        }
    }

    pub fn kind(&self) -> BlanketDirectiveKind {
        self.kind
    }

    pub fn label(&self) -> &Label<'_> {
        &self.label
    }

    pub fn arg_index(&self) -> Option<usize> {
        self.arg_index
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
/// A target is primarily identified by a member path, which is composed of a
/// fully qualified Go package path ([`Self::package_path`]), the declared
/// name of the member ([`Self::member_name`]), as well as an optional receiver
/// type name ([`Self::type_name`]) if the target is a type-associated member
/// (i.e., a method or a struct field). Package-level symbols have no defined
/// `type_name` (e.g., `(os, None, Remove)`), while type members carry the
/// receiver type name (e.g., `(database/sql, Some(DB), Query)`).
///
/// Note that non-method symbols are not necessarily functions, as they may
/// refer to variables and constants (in the case of blanket sources).
/// Analogously, type members are not necessarily methods, and may refer to
/// struct fields (e.g., `(net/http, Some(Request), Body)`).
///
/// In addition, targets may be optionally narrowed down to specific argument
/// positions via the inclusion of a `#N` suffix (zero-indexed). For instance,
/// `os.WriteFile#1` targets only its second argument. Note, however, that any
/// `arg_index` set for a source directive is ignored, since such restriction is
/// only meaningful for enforcement checks.
///
/// # Parsing and Deserializing
///
/// Often, it is simplest to specify a target as a well-formed [`String`]. Two
/// syntactic forms are supported:
/// - `pkg/path.Func`: a package-level symbol (usually a function); or
/// - `pkg/path.Type.Method`: a method or struct field associated to a named
///   receiver type declared in the specified package.
///
/// Whether a target is a symbol or a type member is disambiguated purely by the
/// number of `.`-separated identifiers following the last `/` of the package
/// path. Two identifiers means `pkg.Func`; three identifiers means
/// `pkg.Type.Method`. This is unambiguous because Go module paths only carry
/// `.`s within slash-separated segments (e.g., `example.com/...`), so the
/// portion after the final `/` cleanly delimits `pkg[.Type].Member`. Standard
/// library paths without slashes (e.g., `os`, `net/http`) work analogously.
///
/// Optionally, a `#N` suffix (zero-indexed) may be included to also specify an
/// `arg_index`. For example, the string `database/sql.DB.Query#0` corresponds
/// to a target with defined `package_path`, `type_name`, `member_name`, and
/// `arg_index`.
///
/// This struct implements [`FromStr`] following this specification, and (if the
/// `toml-config` Cargo feature is enabled) it is used to support automatically
/// deserializing a structured target from a provided string via `serde`.
///
/// Method receivers and struct types are matched irrespective of pointer versus
/// value receiver: `pkg.T.M` applies whether the declared receiver/type is `T`
/// or `*T`, per Go's method-set/struct field semantics. As such, no `*` prefix
/// should be included in `type_name`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlanketDirectiveTarget {
    /// Fully-qualified package path.
    pub package_path: FullPackagePath,
    /// Declared name of the receiver type, when the target is a method/field.
    ///
    /// If `None`, the target is a package-level symbol rather than a
    /// type-associated member.
    pub type_name: Option<String>,
    /// Declared name of the member (symbol, method, or field) in question.
    pub member_name: String,
    /// Zero-based argument index that this directive applies to, if any.
    ///
    /// If `None`, no restriction is imposed.
    pub arg_index: Option<usize>,
}

impl BlanketDirectiveTarget {
    /// Constructs a new target.
    ///
    /// In most cases, it is more convenient to use the existing [`FromStr`]
    /// implementation instead of invoking this method directly (or, if the
    /// `toml-config` Cargo feature is enabled, automatically deserializing
    /// from a string via `serde`).
    #[inline]
    pub fn new(
        package_path: impl Into<FullPackagePath>,
        type_name: Option<impl Into<String>>,
        member_name: impl Into<String>,
        arg_index: Option<usize>,
    ) -> Self {
        Self {
            package_path: package_path.into(),
            type_name: type_name.map(Into::into),
            member_name: member_name.into(),
            arg_index,
        }
    }
}

impl fmt::Display for BlanketDirectiveTarget {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.", self.package_path)?;

        if let Some(type_name) = &self.type_name {
            write!(f, "{type_name}.")?;
        }

        write!(f, "{}", self.member_name)?;

        if let Some(index) = self.arg_index {
            write!(f, "#{index}")?;
        }

        Ok(())
    }
}

impl FromStr for BlanketDirectiveTarget {
    type Err = BlanketDirectiveTargetParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (path, arg_index) = if let Some((path, arg_str)) = s.rsplit_once('#') {
            let arg_index: usize = arg_str
                .parse()
                .map_err(BlanketDirectiveTargetParseError::InvalidArgIndex)?;

            (path, Some(arg_index))
        } else {
            (s, None)
        };

        let (before_last_slash, tail) = match path.rsplit_once('/') {
            Some((prefix, tail)) => (Some(prefix), tail),
            None => (None, path),
        };

        let mut tail_segments = tail.split('.');
        // safe: split always yields at least one element
        let subpackage = tail_segments.next().unwrap();
        let mid_segment = tail_segments.next();
        let last_segment = tail_segments.next();

        if tail_segments.next().is_some() {
            // more than 3 dot-separated identifiers in the last path segment
            return Err(BlanketDirectiveTargetParseError::TooManyMemberSegments);
        }

        let (type_name, member_name) = match (mid_segment, last_segment) {
            (Some(member_name), None) => (None, member_name),
            (Some(type_name), Some(method_name)) => (Some(type_name), method_name),
            (None, _) => {
                // no `.` at all after the last `/`
                return Err(BlanketDirectiveTargetParseError::NoPackageFunctionSeparator);
            }
        };

        if before_last_slash.is_some_and(str::is_empty) || subpackage.is_empty() {
            return Err(BlanketDirectiveTargetParseError::EmptyPackagePath);
        }

        if member_name.is_empty() {
            return Err(BlanketDirectiveTargetParseError::EmptyMemberName);
        }

        if type_name.is_some_and(str::is_empty) {
            return Err(BlanketDirectiveTargetParseError::EmptyTypeName);
        }

        let package_path = match before_last_slash {
            Some(prefix) => format!("{prefix}/{subpackage}"),
            None => subpackage.to_owned(),
        };

        let target = Self {
            package_path,
            type_name: type_name.map(str::to_owned),
            member_name: member_name.to_owned(),
            arg_index,
        };

        Ok(target)
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
    /// No `.` was located separating the package path from the member name.
    NoPackageFunctionSeparator,
    /// More than 3 `.`-separated identifiers was found after the final `/`.
    TooManyMemberSegments,
    /// The provided package path is empty.
    EmptyPackagePath,
    /// The receiver type name is empty.
    EmptyTypeName,
    /// The provided member name is empty.
    EmptyMemberName,
    /// The argument-index portion (after the `#`) is not a valid `usize`.
    InvalidArgIndex(ParseIntError),
}

impl fmt::Display for BlanketDirectiveTargetParseError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPackageFunctionSeparator => {
                f.write_str("blanket directive target has no `.` separator")
            }
            Self::TooManyMemberSegments => f.write_str(
                "blanket directive target has too many `.`-separated identifiers (expected \
                 `pkg.Func` or `pkg.Type.Method`)",
            ),
            Self::EmptyPackagePath => {
                f.write_str("blanket directive target has empty package path")
            }
            Self::EmptyTypeName => f.write_str("blanket directive target has empty type name"),
            Self::EmptyMemberName => f.write_str("blanket directive target has empty member name"),
            Self::InvalidArgIndex(err) => {
                write!(
                    f,
                    "blanket directive target has invalid argument index: {err}"
                )
            }
        }
    }
}

impl error::Error for BlanketDirectiveTargetParseError {
    #[inline]
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::NoPackageFunctionSeparator
            | Self::TooManyMemberSegments
            | Self::EmptyPackagePath
            | Self::EmptyTypeName
            | Self::EmptyMemberName => None,
            Self::InvalidArgIndex(inner) => Some(inner),
        }
    }
}

#[cfg(test)]
mod target_tests {
    use super::*;

    #[test]
    fn parses_bare_function_path() {
        let target: BlanketDirectiveTarget = "os.Remove".parse().unwrap();
        assert_eq!(
            target,
            BlanketDirectiveTarget::new("os", None::<String>, "Remove", None)
        );
    }

    #[test]
    fn parses_arg_targeted_function_path() {
        let target: BlanketDirectiveTarget = "os.WriteFile#1".parse().unwrap();
        assert_eq!(
            target,
            BlanketDirectiveTarget::new("os", None::<String>, "WriteFile", Some(1))
        );
    }

    #[test]
    fn parses_qualified_module_paths() {
        let target: BlanketDirectiveTarget = "example.com/a/b/pkg.Fn#0".parse().unwrap();
        assert_eq!(
            target,
            BlanketDirectiveTarget::new("example.com/a/b/pkg", None::<String>, "Fn", Some(0))
        );
    }

    #[test]
    fn parses_stdlib_method_path() {
        let target: BlanketDirectiveTarget = "database/sql.DB.Query".parse().unwrap();
        assert_eq!(
            target,
            BlanketDirectiveTarget::new("database/sql", Some("DB"), "Query", None)
        );
    }

    #[test]
    fn parses_stdlib_method_path_with_arg_index() {
        let target: BlanketDirectiveTarget = "database/sql.DB.Query#0".parse().unwrap();
        assert_eq!(
            target,
            BlanketDirectiveTarget::new("database/sql", Some("DB"), "Query", Some(0))
        );
    }

    #[test]
    fn parses_bare_stdlib_method_path() {
        // no `/` in the package path: `pkg.Type.Method`
        let target: BlanketDirectiveTarget = "os.File.Read".parse().unwrap();
        assert_eq!(
            target,
            BlanketDirectiveTarget::new("os", Some("File"), "Read", None)
        );
    }

    #[test]
    fn parses_qualified_method_path() {
        let target: BlanketDirectiveTarget =
            "github.com/gin-gonic/gin.Context.Query".parse().unwrap();
        assert_eq!(
            target,
            BlanketDirectiveTarget::new("github.com/gin-gonic/gin", Some("Context"), "Query", None)
        );
    }

    #[test]
    fn round_trips_through_display() {
        for input in [
            "os.Remove",
            "os.WriteFile#1",
            "example.com/a/b/pkg.Fn#0",
            "database/sql.DB.Query",
            "database/sql.DB.QueryContext#1",
            "github.com/gin-gonic/gin.Context.Query",
        ] {
            let target: BlanketDirectiveTarget = input.parse().unwrap();
            assert_eq!(target.to_string(), input);
        }
    }

    #[test]
    fn rejects_too_many_member_segments() {
        assert!(matches!(
            "pkg.A.B.C".parse::<BlanketDirectiveTarget>(),
            Err(BlanketDirectiveTargetParseError::TooManyMemberSegments)
        ));
    }

    #[test]
    fn rejects_empty_type_name() {
        assert!(matches!(
            "pkg..Method".parse::<BlanketDirectiveTarget>(),
            Err(BlanketDirectiveTargetParseError::EmptyTypeName)
        ));
    }

    #[test]
    fn rejects_no_separator() {
        assert!(matches!(
            "#0".parse::<BlanketDirectiveTarget>(),
            Err(BlanketDirectiveTargetParseError::NoPackageFunctionSeparator)
        ));
    }

    #[test]
    fn rejects_empty_pkg_path() {
        assert!(matches!(
            ".func#0".parse::<BlanketDirectiveTarget>(),
            Err(BlanketDirectiveTargetParseError::EmptyPackagePath)
        ));
    }

    #[test]
    fn rejects_empty_member_name() {
        assert!(matches!(
            "pkg.#0".parse::<BlanketDirectiveTarget>(),
            Err(BlanketDirectiveTargetParseError::EmptyMemberName)
        ));
    }

    #[test]
    fn rejects_non_numeric_arg_index() {
        assert!(matches!(
            "os.Remove#abc".parse::<BlanketDirectiveTarget>(),
            Err(BlanketDirectiveTargetParseError::InvalidArgIndex(_))
        ));
    }
}
