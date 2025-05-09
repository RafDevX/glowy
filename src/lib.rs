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
//! ```
//! let mut analyzer = glowy::Analyzer::from_directory("./proj")?.expect("module path");
//!
//! let result = analyzer.analyze();
//! ```

#![warn(missing_docs)]
#![deny(rustdoc::unescaped_backticks)]

use std::path::{Path, PathBuf};

pub use analyzer::Analyzer;
pub use files::SourceFile;
use parser::Span;

mod analyzer;
mod context;
mod decls;
pub mod errors;
mod files;
pub mod labels;
mod symbols;
mod taint;

type FullPackagePath = String; // e.g. example.com/org/something/auth
                               // ^ note that auth is not necessarily the package name!
                               // must check package clause for files in auth/

/// Source file content snippet bound to a specific location.
///
/// This is a wrapper over [`Span`] that records contextual information
/// regarding which file the content was found in. [`Span`] already has
/// information on where within a file some content is located, and this
/// struct complements it by further scoping the [`Span`] to a specific
/// file (by virtual path, rooted in the module base).
#[derive(Clone, Debug, PartialEq)]
pub struct ScopedSpan<'a> {
    virtual_file_path: PathBuf,
    span: Span<'a>,
}

impl<'a> ScopedSpan<'a> {
    fn new(virtual_file_path: PathBuf, span: Span<'a>) -> Self {
        Self {
            virtual_file_path,
            span,
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
    /// The returned [`Span`] is sufficient to locate the content within the
    /// specific file, and additionally includes the snippet itself, accessible
    /// via [`Span::content`].
    pub fn span(&self) -> &Span<'a> {
        &self.span
    }

    /// Returns the underlying source code snippet.
    ///
    /// This method is simply a convenient short-hand for invoking
    /// [`Span::content`] on the result of [`ScopedSpan::span`].
    pub fn content(&self) -> &'a str {
        self.span.content()
    }
}
