//! # Glowy
//!
//! Glowy is a static analyzer that examines Go code and attempts to detect
//! insecure information flows (like printing a password). It strives to support
//! a significant portion of language constructs (per the
//! [spec](https://go.dev/ref/spec)) and tries to catch even moderately complex
//! security flaws (like only setting an HTTP header if a secret `seed` is odd).
//! In essence, Glowy helps developers and other stakeholders find potential
//! issues early at compile-time before it becomes a problem.
//!
//! This library allows Rust code to programmatically analyze Go programs with
//! flexibility. **If you just want to run an analysis tool directly from the
//! command-line, check out the binary at <https://github.com/RafDevX/glowy>!**
//!
//! ## Example Usage
//!
//! ```no_run
//! let analyzer = glowy::Analyzer::from_directory("./proj")?;
//!
//! let result = analyzer.analyze();
//! #
//! # Ok::<(), glowy::AnalyzerFromDirectoryError>(())
//! ```

// Clippy lint configuration
#![warn(
    // Lint Groups
    clippy::all,
    clippy::pedantic,
    clippy::cargo,
    // From clippy::restriction (should not be enabled as a group)
    clippy::allow_attributes,
    clippy::allow_attributes_without_reason,
    clippy::as_pointer_underscore,
    clippy::as_underscore,
    clippy::assertions_on_result_states,
    clippy::cfg_not_test,
    clippy::clone_on_ref_ptr,
    clippy::create_dir,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::default_numeric_fallback,
    clippy::deref_by_slicing,
    clippy::disallowed_script_idents,
    clippy::doc_include_without_cfg,
    clippy::doc_paragraphs_missing_punctuation,
    clippy::empty_drop,
    clippy::empty_enum_variants_with_brackets,
    clippy::empty_structs_with_brackets,
    clippy::error_impl_error,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    clippy::exit,
    clippy::field_scoped_visibility_modifiers,
    clippy::filetype_is_file,
    clippy::float_cmp_const,
    clippy::fn_to_numeric_cast_any,
    clippy::get_unwrap,
    clippy::infinite_loop,
    clippy::iter_over_hash_type,
    clippy::large_include_file,
    clippy::let_underscore_untyped,
    clippy::lossy_float_literal,
    clippy::map_err_ignore,
    clippy::map_with_unused_argument_over_ranges,
    clippy::mem_forget,
    clippy::missing_assert_message,
    clippy::missing_inline_in_public_items,
    clippy::mixed_read_write_in_expression,
    clippy::mod_module_files,
    clippy::module_name_repetitions,
    clippy::multiple_inherent_impl,
    clippy::multiple_unsafe_ops_per_block,
    clippy::needless_raw_strings,
    clippy::non_zero_suggestions,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::partial_pub_fields,
    clippy::pathbuf_init_then_push,
    clippy::pointer_format,
    clippy::precedence_bits,
    clippy::print_stderr,
    clippy::pub_without_shorthand,
    clippy::rc_buffer,
    clippy::rc_mutex,
    clippy::redundant_test_prefix,
    clippy::redundant_type_annotations,
    clippy::ref_patterns,
    clippy::renamed_function_params,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::return_and_then,
    clippy::same_name_method,
    clippy::semicolon_inside_block,
    clippy::shadow_same,
    clippy::shadow_unrelated,
    clippy::str_to_string,
    clippy::string_lit_chars_any,
    clippy::string_slice,
    clippy::suspicious_xor_used_as_pow,
    clippy::tests_outside_test_module,
    clippy::todo,
    clippy::try_err,
    clippy::undocumented_unsafe_blocks,
    clippy::unimplemented,
    clippy::unnecessary_safety_comment,
    clippy::unnecessary_safety_doc,
    clippy::unnecessary_self_imports,
    clippy::unneeded_field_pattern,
    clippy::unseparated_literal_suffix,
    clippy::unused_result_ok,
    clippy::verbose_file_reads,
    clippy::wildcard_enum_match_arm,
    // From clippy::nursery (check for open issues before enabling each lint)
    clippy::as_ptr_cast_mut,
    clippy::branches_sharing_code,
    clippy::clear_with_drain,
    clippy::coerce_container_to_any,
    clippy::collection_is_never_read,
    clippy::debug_assert_with_mut_call,
    clippy::derive_partial_eq_without_eq,
    clippy::doc_link_code,
    clippy::equatable_if_let,
    clippy::fallible_impl_from,
    clippy::imprecise_flops,
    clippy::iter_on_empty_collections,
    clippy::iter_on_single_items,
    clippy::iter_with_drain,
    clippy::large_stack_frames,
    clippy::literal_string_with_formatting_args,
    clippy::needless_collect,
    clippy::needless_type_cast,
    clippy::non_send_fields_in_send_ty,
    clippy::nonstandard_macro_braces,
    clippy::or_fun_call,
    clippy::path_buf_push_overwrite,
    clippy::read_zero_byte_vec,
    clippy::redundant_clone,
    clippy::redundant_pub_crate,
    clippy::search_is_some,
    clippy::set_contains_or_insert,
    clippy::significant_drop_in_scrutinee,
    clippy::significant_drop_tightening,
    clippy::single_option_map,
    clippy::string_lit_as_bytes,
    clippy::suboptimal_flops,
    clippy::suspicious_operation_groupings,
    clippy::too_long_first_doc_paragraph,
    clippy::trailing_empty_array,
    clippy::trait_duplication_in_bounds,
    clippy::trivial_regex,
    clippy::tuple_array_conversions,
    clippy::type_repetition_in_bounds,
    clippy::unnecessary_struct_initialization,
    clippy::unused_peekable,
    clippy::unused_rounding,
    clippy::use_self,
    clippy::useless_let_if_seq,
    clippy::while_float,
)]
// Documentation lint configuration
#![warn(missing_docs)]
#![deny(rustdoc::all)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Forbid unsafe code
#![deny(unsafe_code)]

#[cfg(feature = "base-security-policy")]
use std::collections::HashSet;
use std::{borrow::Cow, cmp, fmt, path::Path, sync::LazyLock};

pub use analyzer::{Analyzer, AnalyzerFromDirectoryError};
pub use build_constraints::{DEFAULT_MAX_BUILD_PERMUTATIONS, MAX_ENUMERATED_BUILD_WORLDS};
pub use files::SourceFile;
pub use glowy_go_parser::{Diagnostics as ParsingDiagnostics, Location, Span};
use indexmap::IndexMap;
use policy::{BlanketDirectiveTarget, SinkDescriptor};

mod analyzer;
mod build_constraints;
mod context;
mod decls;
pub mod errors;
mod files;
pub mod labels;
pub mod policy;
mod snapshots;
mod symbols;
mod taint;
mod types;
mod values;

/// Highest supported Go version.
///
/// Glowy assumes that all input is fully compliant with this version of the Go
/// spec, as identified by a tuple `(major, minor)`, e.g. `(1, 26)` for Go 1.26.
///
/// When evaluating build-tag constraints from `//go:build` or legacy
/// `// +build` directives, all versions up to this one are considered satisfied
/// while any others are not; for instance, `//go:build !go1.999` will always be
/// included, since `go1.999` evaluates to `false`.
const SUPPORTED_GO_VERSION: (u32, u32) = (1, 26);

/// Represents an unknown source-file location.
///
/// This standardizes one unified fake configuration that is used throughout the
/// library to serve as a placeholder for when a [`Pinned`] [`Location`] is
/// required, but one simply is not available, for a myriad of possible reasons.
/// A fake location is used when an [`Option`] would greatly increase complexity
/// for very narrow edge-cases, especially for internal processing that is never
/// visible outside the library's private state.
///
/// Consumers may choose to assign special semantics when displaying or
/// manipulating a location that matches this object. It is an error to attempt
/// to obtain a source code snippet at a location matching this object, since
/// either it does not exist, or it is meaningless (i.e., unrelated to where
/// the location was found, and not bound to its semantics).
///
/// If a bare (not-[`Pinned`]) [`Location`] object is necessary, one can be
/// obtained through [`Pinned::inner`].
///
/// Note that a `static` is used instead of a `const` binding because the
/// [`Path::new`] constructor is not `const` (see
/// [RFC 3762](https://github.com/rust-lang/rfcs/pull/3762)), so we use a
/// [`LazyLock`] to ensure one-time initialization (upon first access).
pub static FAKE_LOCATION: LazyLock<Pinned<Location>> = LazyLock::new(|| {
    Pinned::new(
        "/main.go", // should exist in most cases
        0..1,
    )
});

/// Represents an unknown source-code snippet.
///
/// This standardizes one unified fake configuration that is used throughout the
/// library to serve as a placeholder for when a [`Pinned`] [`Span`] is
/// required, but one simply is not available, for a myriad of possible reasons.
/// A fake span is used when an [`Option`] would greatly increase complexity
/// for very narrow edge-cases, especially for internal processing that is never
/// visible outside the library's private state.
///
/// Consumers may choose to assign special semantics when displaying or
/// manipulating a [`Span`] that matches this object. It is an error to attempt
/// to obtain a source code snippet at the location of a [`Span`] matching this
/// object, since either it does not exist, or it is meaningless (i.e.,
/// unrelated to where the snippet was found, and not bound to its semantics).
///
/// If a bare (not-[`Pinned`]) [`Span`] object is necessary, one can be
/// obtained through [`Pinned::inner`].
///
/// Note that a `static` is used instead of a `const` binding because the
/// [`Path::new`] constructor is not `const` (see
/// [RFC 3762](https://github.com/rust-lang/rfcs/pull/3762)), so we use a
/// [`LazyLock`] to ensure one-time initialization (upon first access).
pub static FAKE_SPAN: LazyLock<Pinned<Span<'static>>> = LazyLock::new(|| {
    Pinned::new(
        "/main.go", // should exist in most cases
        Span::new("unknown", 0),
    )
});

type FullPackagePath = String; // e.g. example.com/org/something/auth
// ^ note that auth is not necessarily the package name!
// must check package clause for files in auth/

/// Represents a structured collection of analysis configuration options.
///
/// This aggregates various customizable values and is primarily used as an
/// input to [`Analyzer::new_with_config`]. It may be created manually,
/// or it may be automatically derived from a TOML configuration file using the
/// [`Analyzer::new_with_config_file`] method if Cargo feature `toml-config` is
/// enabled. Similarly, deserialization and ingestion is automatic under
/// [`Analyzer::from_directory`] if a `glowy.toml` file is found in the
/// root of the specified directory and the `toml-config` Cargo feature is
/// enabled.
///
/// Note that the [`Default`] trait is implemented, meaning that it can be used
/// to automatically populate default configuration values when manually
/// constructing an instance.
#[cfg_attr(
    not(feature = "toml-config"),
    expect(
        rustdoc::broken_intra_doc_links,
        reason = "Describe feature-specific API functionality"
    )
)]
#[cfg_attr(
    feature = "base-security-policy",
    expect(clippy::struct_excessive_bools, reason = "Independent options")
)]
#[cfg_attr(feature = "toml-config", derive(serde::Deserialize), serde(default))]
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AnalysisConfig {
    /// Whether to output more detailed status information during the analysis.
    ///
    /// Note that setting this to `false` has no effect if the environment
    /// variable `GLOWY_VERBOSE` is set (in which case the analyzer is always
    /// verbose).
    pub verbose: bool,
    /// Whether to compose all configuration onto Glowy's base security policy.
    ///
    /// When Cargo feature `base-security-policy` is enabled, Glowy ships with a
    /// default, standard security policy designed for supporting a softer
    /// bootstrap curve for stakeholders to start using the provided analysis
    /// features. This base policy (accessible at
    /// [`policy::BASE_SECURITY_POLICY`]) is heuristics-driven and
    /// domain-agnostic, meaning that it will often be wrong in many fronts. It
    /// is designed as a starting resource, under the expectation of being
    /// replaced by a custom security policy before any serious use. When such a
    /// (more adequate) policy exists, the base configuration should be disabled
    /// by setting this option to `false`.
    ///
    /// Specific directives can be disabled via
    /// [`AnalysisConfig::excluded_base_blanket_directives`].
    ///
    /// Defaults to `true`, but is only present with Cargo feature
    /// `base-security-policy` enabled (which it is, by default).
    #[cfg(feature = "base-security-policy")]
    #[cfg_attr(docsrs, doc(cfg(feature = "base-security-policy")))]
    pub inherit_base_policy: bool,
    /// Targets for which blanket directives in Glowy's base policy are ignored.
    ///
    /// When Cargo feature `base-security-policy` is enabled and
    /// [`AnalysisConfig::inherit_base_policy`] is enabled, Glowy ingests its
    /// standard, foundational security policy (accessible at
    /// [`policy::BASE_SECURITY_POLICY`]), comprised of heuristics-driven
    /// and domain-agnostic defaults. Due to its impersonal nature, it is common
    /// (and recommended) to disable all or some of these directives. This
    /// option supports a gradual approach, by allowing consumers to specify
    /// for which specific targets the corresponding blanket directives in the
    /// base security policy should be disregarded.
    ///
    /// Alternatively, the entire base security policy can be disabled by
    /// setting [`AnalysisConfig::inherit_base_policy`] to `false`.
    #[cfg(feature = "base-security-policy")]
    #[cfg_attr(docsrs, doc(cfg(feature = "base-security-policy")))]
    pub excluded_base_blanket_directives: HashSet<BlanketDirectiveTarget>,
    /// Targets universally recognized as blanket information sources.
    ///
    /// These targets will always be considered to yield the associated label,
    /// in addition to what is already otherwise derived from the function body.
    ///
    /// An [`IndexMap`] is used to preserve insertion order. Each key is a
    /// [`BlanketDirectiveTarget`], which deserializes from a string of the form
    /// `pkg.func` (applying to every access), `pkg.func->R,S,...` (applying
    /// only to the results at the selected 0-indexed positions, for callable
    /// sources), or `pkg.func#N=value`/`pkg.func->R,S,...#N=value`
    /// (additionally requiring that the argument in 0-indexed position `N` is
    /// not provably different from `value`, optionally employing fuzzy matching
    /// with `~=`). Each associated [`Vec<String>`] value represents a
    /// [`Label`](labels::Label), with each individual [`String`] element
    /// corresponding to a [`LabelTag::Concrete`](labels::LabelTag::Concrete).
    pub sources: IndexMap<BlanketDirectiveTarget, Vec<String>>,
    /// Targets universally recognized as subject to blanket label revocation.
    ///
    /// Every access to one of these targets has the associated label subtracted
    /// from its calculated value.
    ///
    /// An [`IndexMap`] is used to preserve insertion order. Each key is a
    /// [`BlanketDirectiveTarget`], which deserializes from a string of the form
    /// `pkg.func` (applying to every access), `pkg.func->R,S,...` (applying
    /// only to the results at the selected 0-indexed positions, for callable
    /// revocation targets), or `pkg.func#N=value`/`pkg.func->R,S,...#N=value`
    /// (additionally requiring that the argument in 0-indexed position `N` is
    /// not provably different from `value`, optionally employing fuzzy matching
    /// with `~=`). Each associated [`Vec<String>`] value represents a
    /// [`Label`](labels::Label), with each individual [`String`] element
    /// corresponding to a [`LabelTag::Concrete`](labels::LabelTag::Concrete).
    pub revocations: IndexMap<BlanketDirectiveTarget, Vec<String>>,
    /// Targets universally recognized as blanket whitelist-based sinks.
    ///
    /// These targets will always be considered to accept only values up to
    /// the associated label, after the value's calculated label has been
    /// [restricted](labels::Label::restrict_to_axes) to the sink's label.
    ///
    /// An [`IndexMap`] is used to preserve insertion order. Each key is a
    /// [`BlanketDirectiveTarget`], which deserializes from a string of the form
    /// `pkg.func` (applying to every argument) or `pkg.func#N` (applying only
    /// to the argument at position `N`, 0-indexed). Each associated
    /// [`Vec<String>`] value represents a [`Label`](labels::Label), with each
    /// individual [`String`] element corresponding to a
    /// [`LabelTag::Concrete`](labels::LabelTag::Concrete).
    pub allow_sinks: IndexMap<BlanketDirectiveTarget, Vec<String>>,
    /// Targets universally recognized as blanket blacklist-based sinks.
    ///
    /// These targets will always be considered to accept only values with
    /// null intersection with the associated label.
    ///
    /// An [`IndexMap`] is used to preserve insertion order. Each key is a
    /// [`BlanketDirectiveTarget`], which deserializes from a string of the form
    /// `pkg.func` (applying to every argument) or `pkg.func#N` (applying only
    /// to the argument at position `N`, 0-indexed). Each associated
    /// [`Vec<String>`] value represents a [`Label`](labels::Label), with each
    /// individual [`String`] element corresponding to a
    /// [`LabelTag::Concrete`](labels::LabelTag::Concrete).
    pub deny_sinks: IndexMap<BlanketDirectiveTarget, Vec<String>>,
    /// Whether to include `_test.go` files in the analysis.
    ///
    /// Defaults to `false`, matching the behavior of `go build` (test files
    /// are only compiled by `go test`). Set to `true` to also analyze tests.
    pub include_tests: bool,
    /// Maximum number of distinct build permutations to analyze.
    ///
    /// `//go:build` directives and GOOS/GOARCH-style filename suffixes each
    /// introduce a boolean dimension whose `2^N` on/off combinations the
    /// analyzer would otherwise explore in full. Each combination is a separate
    /// world (permutation) that admits some set of files to be analyzed.
    ///
    /// Build-tag constraints that admit the same set of files count as one
    /// permutation. If the corpus produces more distinct admitted-file sets
    /// than this cap, analysis aborts with a
    /// [`TooManyBuildPermutations`][AEKtmbp] error so the invoker can decide
    /// whether to raise the cap and retry.
    ///
    /// Defaults to [`DEFAULT_MAX_BUILD_PERMUTATIONS`].
    ///
    /// [AEKtmbp]: errors::AnalysisErrorKind::TooManyBuildPermutations
    pub max_build_permutations: usize,
    /// Whether to report statements detected after block-terminating others.
    ///
    /// While unreachable code (and code detected as unreachable, in general) is
    /// a sign that something is probably wrong, it is still valid Go and its
    /// existence does not compromise analysis results, so it can make sense
    /// both to flag and not to flag unreachable code, depending on the error
    /// handling pipeline and its sensitivity to any reported diagnostics.
    ///
    /// If this configuration option is set to `false`, any
    /// [`errors::AnalysisError`] that would be reported with
    /// [`errors::AnalysisErrorKind::Unreachable`] are instead silently
    /// discarded.
    ///
    /// Defaults to `false`.
    pub report_unreachable: bool,
}

impl Default for AnalysisConfig {
    #[inline]
    fn default() -> Self {
        Self {
            verbose: false,
            #[cfg(feature = "base-security-policy")]
            inherit_base_policy: true,
            #[cfg(feature = "base-security-policy")]
            excluded_base_blanket_directives: HashSet::new(),
            sources: IndexMap::new(),
            revocations: IndexMap::new(),
            allow_sinks: IndexMap::new(),
            deny_sinks: IndexMap::new(),
            include_tests: false,
            max_build_permutations: DEFAULT_MAX_BUILD_PERMUTATIONS,
            report_unreachable: false,
        }
    }
}

/// Object, component, or metadata bound to a specific file.
///
/// This is a wrapper over an inner type `T` that records contextual information
/// regarding which file the underlying entity relates to. Usually, within
/// Glowy, this is used with an inner type of either [`Span`] or [`Location`].
///
/// Both [`Span`] and [`Location`] already have information on where within a
/// file some content is located, and this struct complements it by further
/// scoping its inner instance to a specific file (by virtual path, rooted in
/// the module base).
#[derive(Clone, Copy, Debug, PartialEq, Hash)]
pub struct Pinned<'a, T: Clone + fmt::Debug + PartialEq> {
    virtual_file_path: &'a Path,
    inner: T,
}

impl<T: Eq + Clone + fmt::Debug> Eq for Pinned<'_, T> {}

impl<'a, T: Clone + fmt::Debug + PartialEq> Pinned<'a, T> {
    /// Constructs a new [`Pinned`] value bound to a specific file.
    ///
    /// The value passed as an argument to `virtual_file_path` may be anything
    /// borrowed and [`Path`]-like, such as [`&str`](str), [`&Path`](Path), or
    /// [`&PathBuf`](std::path::PathBuf), with the resulting [`Pinned`] instance
    /// then living for as long as that reference's lifetime. However, care
    /// should be taken to pass a valid virtual file path that satisfies the
    /// invariants assumed by [`Pinned`] (e.g., the path must be rooted and
    /// represent a Go source file relative to the module base).
    #[inline]
    pub fn new<P: AsRef<Path> + ?Sized>(virtual_file_path: &'a P, inner: T) -> Self {
        Self {
            virtual_file_path: virtual_file_path.as_ref(),
            inner,
        }
    }

    /// Returns the file where the content was found.
    ///
    /// The returned [`Path`] is always rooted and bound to the Go module base.
    #[inline]
    pub fn file(&self) -> &'a Path {
        self.virtual_file_path
    }

    /// Returns the underlying intra-file information.
    ///
    /// The returned instance is often sufficient to locate the content within
    /// the specific file, and in the case of [`Span`] additionally includes the
    /// snippet itself, accessible via [`Span::content`] (see also the
    /// short-hand [`Pinned::content`]).
    #[inline]
    pub fn inner(&self) -> &T {
        &self.inner
    }
}

impl<'p, 'a> Pinned<'p, Span<'a>> {
    /// Returns the underlying source code snippet.
    ///
    /// This method is simply a convenient short-hand for invoking
    /// [`Span::content`] on the result of [`Pinned::inner`] when the inner type
    /// is [`Span`].
    #[must_use]
    #[inline]
    pub fn content(&self) -> &'a str {
        self.inner().content()
    }

    /// Returns a new instance qualifying the underlying [`Span`]'s location.
    ///
    /// This method uses [`Span::location`] to construct a new [`Pinned`] with
    /// inner type [`Location`]. The same virtual file path is used (copied).
    #[must_use]
    #[inline]
    pub fn pinned_location(&self) -> Pinned<'p, Location> {
        Pinned::new(self.virtual_file_path, self.inner().location())
    }
}

impl Pinned<'_, Location> {
    /// Returns whether this [`Pinned<Location>`] is physically within another.
    ///
    /// This method does not consider `self` to be contained in `other` unless
    /// they both refer to the same file and `self`'s underlying [`Location`]
    /// is the same as or is fully contained within `other`'s.
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::Pinned;
    /// #
    /// let base = Pinned::new("/main.go", 12..27);
    /// let x = Pinned::new("/main.go", 16..20);
    /// let y = Pinned::new("/main.go", 16..30);
    /// let z = Pinned::new("/other.go", 16..20);
    ///
    /// assert!(base.contained_in(&base));
    /// assert!(x.contained_in(&base));
    /// assert!(!y.contained_in(&base));
    /// assert!(!z.contained_in(&base));
    /// ```
    #[must_use]
    #[inline]
    pub fn contained_in(&self, other: &Self) -> bool {
        self.file() == other.file()
            && self.inner().start >= other.inner().start
            && self.inner().end <= other.inner().end
    }
}

impl Ord for Pinned<'_, Span<'_>> {
    #[inline]
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.virtual_file_path
            .cmp(other.virtual_file_path)
            .then(self.inner().location().cmp(other.inner().location()))
            .then(self.content().cmp(other.content()))
    }
}

impl PartialOrd for Pinned<'_, Span<'_>> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd for Pinned<'_, Location> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        if self.virtual_file_path != other.virtual_file_path {
            // not comparable on different files
            return None;
        }

        if self.inner == other.inner {
            return Some(cmp::Ordering::Equal);
        }

        // we return an ordering only if the start is clearly distinct
        // and one location is not contained in the other

        match self.inner.start.cmp(&other.inner.start) {
            cmp::Ordering::Less => {
                if self.inner.end < other.inner.end {
                    Some(cmp::Ordering::Less)
                } else {
                    None
                }
            }
            cmp::Ordering::Greater => {
                if self.inner.end > other.inner.end {
                    Some(cmp::Ordering::Greater)
                } else {
                    None
                }
            }
            cmp::Ordering::Equal => None,
        }
    }
}

/// Functionality relating to easy conversion to a [`Cow<'a, str>`].
///
/// This trait allows consumers to accept various different types that can be
/// unified and converted into a [`Cow<'a, str>`] without requiring additional
/// allocations. An existing [`String`] has its ownership preserved as a
/// [`Cow::Owned`], while any references or slices (such as `&str` or `&String`)
/// become [`Cow::Borrowed`] and maintain their underlying lifetime.
///
/// While [`Into<Cow<'a, str>>`] would already solve [`AsRef<str>`] this problem
/// for some of the supported types, [`IntoCowStr`] is more generic and more
/// extensible. In particular, it is implemented for `&String`, making it very
/// useful in flexible contexts.
pub trait IntoCowStr<'a> {
    /// Consumes a value and converts it into a clone-on-write string.
    #[must_use]
    fn into_cow(self) -> Cow<'a, str>;
}

impl<'a> IntoCowStr<'a> for &'a str {
    #[inline]
    fn into_cow(self) -> Cow<'a, str> {
        Cow::Borrowed(self)
    }
}

impl<'a> IntoCowStr<'a> for &&'a str {
    #[inline]
    fn into_cow(self) -> Cow<'a, str> {
        Cow::Borrowed(*self)
    }
}

impl<'a> IntoCowStr<'a> for String {
    #[inline]
    fn into_cow(self) -> Cow<'a, str> {
        Cow::Owned(self)
    }
}

impl<'a> IntoCowStr<'a> for &'a String {
    #[inline]
    fn into_cow(self) -> Cow<'a, str> {
        Cow::Borrowed(self.as_str())
    }
}
