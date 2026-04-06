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
//! let mut analyzer = glowy::Analyzer::from_directory("./proj")?.expect("module path");
//!
//! let result = analyzer.analyze();
//! #
//! # Ok::<(), std::io::Error>(())
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
    clippy::as_underscore,
    clippy::assertions_on_result_states,
    clippy::cfg_not_test,
    clippy::clone_on_ref_ptr,
    clippy::create_dir,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::default_numeric_fallback, // probably not?
    clippy::deref_by_slicing,
    clippy::doc_include_without_cfg,
    clippy::empty_enum_variants_with_brackets,
    clippy::empty_structs_with_brackets,
    clippy::error_impl_error,
    clippy::exit,
    clippy::field_scoped_visibility_modifiers,
    clippy::filetype_is_file,
    clippy::float_cmp_const,
    clippy::fn_to_numeric_cast_any,
    clippy::get_unwrap,
    clippy::infinite_loop,
    clippy::iter_over_hash_type,
    clippy::lossy_float_literal,
    clippy::map_err_ignore,
    clippy::map_with_unused_argument_over_ranges,
    clippy::missing_assert_message,
    clippy::missing_inline_in_public_items,
    clippy::mixed_read_write_in_expression,
    clippy::mod_module_files,
    clippy::module_name_repetitions,
    clippy::multiple_inherent_impl,
    clippy::multiple_unsafe_ops_per_block,
    clippy::needless_raw_strings,
    clippy::panic_in_result_fn,
    clippy::partial_pub_fields,
    clippy::pathbuf_init_then_push,
    clippy::precedence_bits,
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
    clippy::unnecessary_safety_comment,
    clippy::unnecessary_safety_doc,
    clippy::unnecessary_self_imports,
    clippy::unneeded_field_pattern,
    clippy::unseparated_literal_suffix,
    clippy::unused_result_ok,
    clippy::verbose_file_reads,
    clippy::wildcard_enum_match_arm,
    // From clippy::nursery (check for open issues before enabling each lint)
    clippy::branches_sharing_code,
    clippy::clear_with_drain,
    clippy::collection_is_never_read,
    clippy::debug_assert_with_mut_call,
    clippy::derive_partial_eq_without_eq,
    clippy::doc_link_code,
    clippy::equatable_if_let,
    clippy::fallible_impl_from,
    clippy::iter_on_empty_collections,
    clippy::iter_on_single_items,
    clippy::iter_with_drain,
    clippy::large_stack_frames,
    clippy::literal_string_with_formatting_args,
    clippy::needless_collect,
    clippy::nonstandard_macro_braces,
    clippy::or_fun_call,
    clippy::path_buf_push_overwrite,
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
#![expect(
    clippy::multiple_crate_versions,
    reason = "Some sub-dependencies require different versions of the same crates"
)]
// Documentation lint configuration
#![warn(missing_docs)]
#![deny(rustdoc::unescaped_backticks)]

use std::{
    cmp, fmt,
    path::{Path, PathBuf},
};

pub use analyzer::Analyzer;
pub use files::SourceFile;
pub use parser::{Diagnostics as ParsingDiagnostics, Location, Span};
pub use taint::{SinkDescriptor, SinkKind};

mod analyzer;
mod context;
mod decls;
pub mod errors;
mod files;
pub mod labels;
mod snapshots;
mod symbols;
mod taint;
mod values;

type FullPackagePath = String; // e.g. example.com/org/something/auth
// ^ note that auth is not necessarily the package name!
// must check package clause for files in auth/

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
#[derive(Clone, Debug, PartialEq)]
pub struct Pinned<T: Clone + fmt::Debug + PartialEq> {
    virtual_file_path: PathBuf,
    inner: T,
}

impl<T: Eq + Clone + fmt::Debug> Eq for Pinned<T> {}

impl<T: Clone + fmt::Debug + PartialEq> Pinned<T> {
    fn new(virtual_file_path: PathBuf, inner: T) -> Self {
        Self {
            virtual_file_path,
            inner,
        }
    }

    /// Returns the file where the content was found.
    ///
    /// The returned [`Path`] is always rooted and bound to the Go module base.
    #[inline]
    pub fn file(&self) -> &Path {
        &self.virtual_file_path
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

impl<'a> Pinned<Span<'a>> {
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
    /// inner type [`Location`]. The same virtual file path is used (cloned).
    #[must_use]
    #[inline]
    pub fn pinned_location(&self) -> Pinned<Location> {
        Pinned {
            virtual_file_path: self.virtual_file_path.clone(),
            inner: self.inner().location(),
        }
    }
}

impl Ord for Pinned<Span<'_>> {
    #[inline]
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.virtual_file_path
            .cmp(&other.virtual_file_path)
            .then(self.inner().location().cmp(other.inner().location()))
            .then(self.content().cmp(other.content()))
    }
}

impl PartialOrd for Pinned<Span<'_>> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd for Pinned<Location> {
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
