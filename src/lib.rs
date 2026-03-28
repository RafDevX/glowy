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
#![warn(clippy::all, clippy::pedantic, clippy::cargo)]
#![allow(clippy::option_option)]
// Documentation lint configuration
#![warn(missing_docs)]
#![deny(rustdoc::unescaped_backticks)]

use std::{
    cmp, fmt,
    path::{Path, PathBuf},
};

pub use analyzer::Analyzer;
pub use files::SourceFile;
use parser::{Location, Span};
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

/// Source file content snippet bound to a specific location.
///
/// This is a wrapper over an inner type `T` that records contextual information
/// regarding which file the underlying content was found in. Usually, within
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
    pub fn file(&self) -> &Path {
        &self.virtual_file_path
    }

    /// Returns the underlying intra-file information.
    ///
    /// The returned instance is often sufficient to locate the content within
    /// the specific file, and in the case of [`Span`] additionally includes the
    /// snippet itself, accessible via [`Span::content`] (see also the
    /// short-hand [`Pinned::content`]).
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
    pub fn content(&self) -> &'a str {
        self.inner().content()
    }

    /// Returns a new instance qualifying the underlying [`Span`]'s location.
    ///
    /// This method uses [`Span::location`] to construct a new [`Pinned`] with
    /// inner type [`Location`]. The same virtual file path is used (cloned).
    #[must_use]
    pub fn pinned_location(&self) -> Pinned<Location> {
        Pinned {
            virtual_file_path: self.virtual_file_path.clone(),
            inner: self.inner().location(),
        }
    }
}

impl Ord for Pinned<Span<'_>> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.virtual_file_path
            .cmp(&other.virtual_file_path)
            .then(self.inner().location().cmp(other.inner().location()))
            .then(self.content().cmp(other.content()))
    }
}

impl PartialOrd for Pinned<Span<'_>> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd for Pinned<Location> {
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
