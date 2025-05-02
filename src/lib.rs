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

pub use analyzer::Analyzer;
pub use files::SourceFile;

mod analyzer;
mod context;
mod files;
