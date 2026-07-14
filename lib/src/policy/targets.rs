use std::{collections::BTreeSet, error, fmt, hash::Hash, num::ParseIntError, str::FromStr};

use crate::{FullPackagePath, values::SimpleConstValue};

/// Canonical pseudo-package path for Go's predeclared symbols.
///
/// The Go documentation presents these symbols under package `builtin`,
/// even though it is not an importable package. Blanket directive targets
/// employ this explicit namespace as a package name to refer to predeclared
/// symbols (e.g., `builtin.len`).
///
/// Specifying the bare member name (e.g., `len`) is not supported as a
/// shorthand during deserialization because it could lead to silent confusion,
/// as invokers could assume that specifying no package would mean the current
/// root package under analysis. It is thus better to report an error when there
/// is no package qualification rather than make assumptions on unknown intent.
pub const BUILTIN_PACKAGE_PATH: &str = "builtin";

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
/// Note that non-method symbols are not necessarily functions, as blanket
/// sources and revocations may refer to variables and constants. Analogously,
/// type members are not necessarily methods, and may refer to struct fields
/// (e.g., `(net/http, Some(Request), Body)`).
///
/// In addition, in the case of functions and methods, sink targets may be
/// optionally narrowed down to specific argument zero-indexed positions via
/// [`Self::arg_index`], and source/revocation targets may be similarly
/// restricted to apply only to specific return value zero-indexed positions
/// ([`Self::result_selector`]) or when a specific argument at a given
/// zero-indexed position is not provably different from a given value.
///
/// In order to target Go builtins and predeclared symbols that would otherwise
/// have no package qualification, [`BUILTIN_PACKAGE_PATH`] should be used as a
/// placeholder in [`Self::package_path`] in order to refer to such cases.
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
/// Optionally, for function and method blanket targets, a `#N` suffix
/// (zero-indexed) may be included to also specify an `arg_index`. For source
/// and revocation directives only, a `->R,S,...` component may follow the
/// member path to select one or more result positions by their zero-based
/// indices (`result_selector`), and the form `#N=value` may be used to record a
/// call-time (case-insensitive) equality predicate, while `~=` can be used
/// instead of `=` to enable fuzzy matching (substring-based). For example, the
/// string `database/sql.DB.Query->0,2#1=users` corresponds to a source or
/// revocation targeting only the first and third results when the second
/// argument could equal `users`.
///
/// Argument predicate values parsed from configuration are intentionally
/// treated as unquoted constants: `#0=123` matches both the string constant
/// `"123"` and the integer constant `123`.
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
    ///
    /// If this matches [`BUILTIN_PACKAGE_PATH`], it qualifies predeclared Go
    /// symbols from the universe scope.
    pub package_path: FullPackagePath,
    /// Declared name of the receiver type, when the target is a method/field.
    ///
    /// If `None`, the target is a package-level symbol rather than a
    /// type-associated member.
    pub type_name: Option<String>,
    /// Declared name of the member (symbol, method, or field) in question.
    pub member_name: String,
    /// Zero-based function result indices affected by this directive.
    ///
    /// If empty, no restriction is imposed. This selector only has meaning
    /// for blanket sources and revocations applied to function or method calls.
    pub result_selector: BTreeSet<usize>,
    /// Zero-based argument index that this sink directive applies to, if any.
    ///
    /// If `None`, no restriction is imposed.
    pub arg_index: Option<usize>,
    /// Argument-based predicate for conditional application of sources.
    ///
    /// While source-oriented, argument predicates also apply to revocations.
    pub arg_predicate: Option<BlanketSourceArgPredicate>,
}

impl BlanketDirectiveTarget {
    /// Constructs a new target for a blanket source or revocation.
    ///
    /// In most cases, it is more convenient to use the existing [`FromStr`]
    /// implementation instead of invoking this method directly (or, if the
    /// `toml-config` Cargo feature is enabled, automatically deserializing
    /// from a string via `serde`).
    #[inline]
    pub fn new_for_source_or_revocation(
        package_path: impl Into<FullPackagePath>,
        type_name: Option<impl Into<String>>,
        member_name: impl Into<String>,
        result_selector: BTreeSet<usize>,
        arg_predicate: Option<BlanketSourceArgPredicate>,
    ) -> Self {
        Self {
            package_path: package_path.into(),
            type_name: type_name.map(Into::into),
            member_name: member_name.into(),
            result_selector,
            arg_index: None,
            arg_predicate,
        }
    }

    /// Constructs a new target for a blanket sink.
    ///
    /// In most cases, it is more convenient to use the existing [`FromStr`]
    /// implementation instead of invoking this method directly (or, if the
    /// `toml-config` Cargo feature is enabled, automatically deserializing
    /// from a string via `serde`).
    #[inline]
    pub fn new_for_sink(
        package_path: impl Into<FullPackagePath>,
        type_name: Option<impl Into<String>>,
        member_name: impl Into<String>,
        arg_index: Option<usize>,
    ) -> Self {
        Self {
            package_path: package_path.into(),
            type_name: type_name.map(Into::into),
            member_name: member_name.into(),
            result_selector: BTreeSet::new(), // only allocates after insertion
            arg_index,
            arg_predicate: None,
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

        let mut result_selector_iter = self.result_selector.iter();
        if let Some(first) = result_selector_iter.next() {
            write!(f, "->{first}")?;

            for index in result_selector_iter {
                write!(f, ",{index}")?;
            }
        }

        if let Some(predicate) = &self.arg_predicate {
            write!(f, "#{predicate}")?;
        } else if let Some(index) = self.arg_index {
            write!(f, "#{index}")?;
        }

        Ok(())
    }
}

impl FromStr for BlanketDirectiveTarget {
    type Err = BlanketDirectiveTargetParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (path, arg_index, arg_predicate) = if let Some((path, arg_spec)) = s.rsplit_once('#') {
            let (arg_str, arg_value_str) = arg_spec
                .split_once('=')
                .map_or((arg_spec, None), |(arg_str, value)| (arg_str, Some(value)));

            let (arg_str, fuzzy) = if let Some(stripped) = arg_str.strip_suffix('~') {
                (stripped, true)
            } else {
                (arg_str, false)
            };

            let arg_index: usize = arg_str
                .parse()
                .map_err(BlanketDirectiveTargetParseError::InvalidArgIndex)?;

            let arg_predicate = arg_value_str
                .map(BlanketSourcePredicateValue::from_str)
                .transpose()?
                .map(|value| BlanketSourceArgPredicate::new(arg_index, value, fuzzy));

            let arg_index = if arg_predicate.is_some() {
                None
            } else {
                Some(arg_index)
            };

            (path, arg_index, arg_predicate)
        } else {
            (s, None, None)
        };

        let (path, result_selector) = if let Some((path, selector)) = path.rsplit_once("->") {
            if selector.is_empty() {
                return Err(BlanketDirectiveTargetParseError::EmptyResultSelector);
            }

            let result_selector = selector
                .split(',')
                .map(|index| {
                    index
                        .parse()
                        .map_err(BlanketDirectiveTargetParseError::InvalidResultIndex)
                })
                .collect::<Result<_, _>>()?;

            (path, result_selector)
        } else {
            (path, BTreeSet::new())
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
            result_selector,
            arg_index,
            arg_predicate,
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

/// Represents an applicability predicate for argument-targeted blanket sources.
///
/// Glowy supports conditionally configuring blanket sources that are only
/// actually effective under specific conditions, based on the inferred value of
/// a specific argument, for an invocable source.
///
/// For example, consumers might find it helpful to declare that `os.Getenv` is
/// a blanket source but only when the value passed to its first argument
/// matches (or could match) `API_TOKEN`. The analyzer would then only apply the
/// blanket source's effects on invocations where it could not statically
/// determine that the value did not match `API_TOKEN`. Note that only very
/// simple value tracking is available, but obvious cases such as
/// `os.GetEnv("PORT")` will not trigger the blanket source.
///
/// Note that while source-oriented, argument predicates are also effective for
/// conditional revocation blanket directives.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlanketSourceArgPredicate {
    arg_index: usize,
    value: BlanketSourcePredicateValue,
    fuzzy: bool,
}

impl BlanketSourceArgPredicate {
    /// Constructs a new argument predicate for the given call argument index.
    ///
    /// If `fuzzy` is `true`, matching is performed much more loosely: an
    /// argument value is considered to match if the predicate value is a
    /// case-insensitive substring of the argument's string representation.
    #[must_use]
    #[inline]
    pub fn new(
        arg_index: usize,
        value: impl Into<BlanketSourcePredicateValue>,
        fuzzy: bool,
    ) -> Self {
        Self {
            arg_index,
            value: value.into(),
            fuzzy,
        }
    }

    /// Returns the zero-based call argument index tested by this predicate.
    #[must_use]
    #[inline]
    pub fn arg_index(&self) -> usize {
        self.arg_index
    }

    /// Returns the constant value tested by this predicate.
    #[must_use]
    #[inline]
    pub fn value(&self) -> &BlanketSourcePredicateValue {
        &self.value
    }

    /// Returns whether this predicate uses fuzzy matching.
    #[must_use]
    #[inline]
    pub fn fuzzy(&self) -> bool {
        self.fuzzy
    }

    pub(crate) fn matches_const(&self, actual: &SimpleConstValue) -> bool {
        if self.fuzzy {
            self.value.matches_fuzzy(actual)
        } else {
            self.value.matches(actual)
        }
    }
}

impl fmt::Display for BlanketSourceArgPredicate {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.arg_index, self.value)
    }
}

/// Constant value used by an argument-targeting blanket source predicate.
///
/// See [`BlanketSourceArgPredicate`] for more information on usage.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BlanketSourcePredicateValue {
    /// A predicate value without a known type.
    ///
    /// Since this value has unknown type, it is considered to match with any
    /// other value (of any other type) with the same string representation.
    /// For example, a [`BlanketSourcePredicateValue::Raw`] holding "123"
    /// matches both a string-typed argument "123" and an integer-shaped
    /// argument 123.
    Raw(String),
    /// A predicate value bound to a specific, known type.
    ///
    /// The wrapped type, `SimpleConstValue`, is an internal representation
    /// available only for very simple expression combinations, such as `5`
    /// derived from `2 + 3`.
    Typed(SimpleConstValue),
}

impl BlanketSourcePredicateValue {
    pub(crate) fn matches(&self, actual: &SimpleConstValue) -> bool {
        match self {
            Self::Typed(SimpleConstValue::String(expected))
                if let SimpleConstValue::String(actual) = actual =>
            {
                expected.to_lowercase() == actual.to_lowercase()
            }
            Self::Typed(expected) => expected == actual,
            Self::Raw(expected) => match actual {
                SimpleConstValue::Boolean(actual) => *expected == actual.to_string(),
                SimpleConstValue::Integer(actual) => expected
                    .parse::<u64>()
                    .is_ok_and(|expected| expected == *actual),
                SimpleConstValue::String(actual) => {
                    expected.to_lowercase() == actual.to_lowercase()
                }
            },
        }
    }

    pub(crate) fn matches_fuzzy(&self, actual: &SimpleConstValue) -> bool {
        let actual = actual.to_string().to_lowercase();
        let expected = self.to_string().to_lowercase();

        actual.contains(&expected)
    }
}

impl fmt::Display for BlanketSourcePredicateValue {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Raw(raw) => f.write_str(raw),
            Self::Typed(value) => value.fmt(f),
        }
    }
}

impl FromStr for BlanketSourcePredicateValue {
    type Err = BlanketDirectiveTargetParseError;

    #[inline]
    fn from_str(raw_value: &str) -> Result<Self, Self::Err> {
        if raw_value.is_empty() {
            return Err(BlanketDirectiveTargetParseError::EmptyArgPredicateValue);
        }

        Ok(Self::Raw(raw_value.to_owned()))
    }
}

impl From<bool> for BlanketSourcePredicateValue {
    #[inline]
    fn from(value: bool) -> Self {
        Self::Typed(SimpleConstValue::Boolean(value))
    }
}

impl From<u64> for BlanketSourcePredicateValue {
    #[inline]
    fn from(value: u64) -> Self {
        Self::Typed(SimpleConstValue::Integer(value))
    }
}

impl From<String> for BlanketSourcePredicateValue {
    #[inline]
    fn from(value: String) -> Self {
        Self::Typed(SimpleConstValue::String(value))
    }
}

impl From<&str> for BlanketSourcePredicateValue {
    #[inline]
    fn from(value: &str) -> Self {
        Self::from(value.to_owned())
    }
}

/// Represents a failure to parse a string into a [`BlanketDirectiveTarget`].
#[derive(Debug)]
pub enum BlanketDirectiveTargetParseError {
    /// A slash-qualified package path had no `.` separating its member name.
    NoPackageFunctionSeparator,
    /// More than 3 `.`-separated identifiers was found after the final `/`.
    TooManyMemberSegments,
    /// The provided package path is empty.
    EmptyPackagePath,
    /// The receiver type name is empty.
    EmptyTypeName,
    /// The provided member name is empty.
    EmptyMemberName,
    /// The provided result selector (after the `->`) has no indices.
    EmptyResultSelector,
    /// A result-selector index is not a valid `usize`.
    InvalidResultIndex(ParseIntError),
    /// The argument-index portion (after the `#`) is not a valid `usize`.
    InvalidArgIndex(ParseIntError),
    /// The provided source argument predicate value is empty.
    EmptyArgPredicateValue,
}

impl fmt::Display for BlanketDirectiveTargetParseError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPackageFunctionSeparator => {
                f.write_str("slash-qualified blanket directive target has no `.` separator")
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
            Self::EmptyArgPredicateValue => {
                f.write_str("blanket directive source argument predicate value is empty")
            }
            Self::EmptyResultSelector => {
                f.write_str("blanket directive target result selector is empty")
            }
            Self::InvalidResultIndex(err) => {
                write!(
                    f,
                    "blanket directive target has invalid result index: {err}"
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
            | Self::EmptyMemberName
            | Self::EmptyResultSelector
            | Self::EmptyArgPredicateValue => None,
            Self::InvalidArgIndex(inner) | Self::InvalidResultIndex(inner) => Some(inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_function_path() {
        let target: BlanketDirectiveTarget = "os.Remove".parse().unwrap();
        assert_eq!(
            target,
            BlanketDirectiveTarget::new_for_sink("os", None::<String>, "Remove", None)
        );
    }

    #[test]
    fn parses_arg_targeted_function_path() {
        let target: BlanketDirectiveTarget = "os.WriteFile#1".parse().unwrap();
        assert_eq!(
            target,
            BlanketDirectiveTarget::new_for_sink("os", None::<String>, "WriteFile", Some(1))
        );
    }

    #[test]
    fn parses_qualified_module_paths() {
        let target: BlanketDirectiveTarget = "example.com/a/b/pkg.Fn#0".parse().unwrap();
        assert_eq!(
            target,
            BlanketDirectiveTarget::new_for_sink(
                "example.com/a/b/pkg",
                None::<String>,
                "Fn",
                Some(0)
            )
        );
    }

    #[test]
    fn parses_stdlib_method_path() {
        let target: BlanketDirectiveTarget = "database/sql.DB.Query".parse().unwrap();
        assert_eq!(
            target,
            BlanketDirectiveTarget::new_for_sink("database/sql", Some("DB"), "Query", None)
        );
    }

    #[test]
    fn parses_stdlib_method_path_with_arg_index() {
        let target: BlanketDirectiveTarget = "database/sql.DB.Query#0".parse().unwrap();
        assert_eq!(
            target,
            BlanketDirectiveTarget::new_for_sink("database/sql", Some("DB"), "Query", Some(0))
        );
    }

    #[test]
    fn parses_bare_stdlib_method_path() {
        // no `/` in the package path: `pkg.Type.Method`
        let target: BlanketDirectiveTarget = "os.File.Read".parse().unwrap();
        assert_eq!(
            target,
            BlanketDirectiveTarget::new_for_sink("os", Some("File"), "Read", None)
        );
    }

    #[test]
    fn parses_qualified_method_path() {
        let target: BlanketDirectiveTarget =
            "github.com/gin-gonic/gin.Context.Query".parse().unwrap();
        assert_eq!(
            target,
            BlanketDirectiveTarget::new_for_sink(
                "github.com/gin-gonic/gin",
                Some("Context"),
                "Query",
                None,
            )
        );
    }

    #[test]
    fn round_trips_through_display() {
        for input in [
            "os.Remove",
            "os.WriteFile#1",
            "builtin.len",
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
    fn slash_qualified_target_still_requires_separator() {
        assert!(matches!(
            "example.com/pkg".parse::<BlanketDirectiveTarget>(),
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

    #[test]
    fn rejects_empty_arg_predicate_value() {
        assert!(matches!(
            "os.Getenv#0=".parse::<BlanketDirectiveTarget>(),
            Err(BlanketDirectiveTargetParseError::EmptyArgPredicateValue)
        ));
    }
}
