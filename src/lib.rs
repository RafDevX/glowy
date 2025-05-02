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
//! let mut analyzer = glowy::Analyzer::new("example.com/company-name/proj");
//!
//! let file = glowy::SourceFile::read_from_disk("/main.go", "./proj/main.go")?;
//! analyzer.add_file(file);
//!
//! let result = analyzer.analyze();
//! ```

#![warn(missing_docs)]
#![deny(rustdoc::unescaped_backticks)]

use std::{
    fs,
    io::{self, BufRead},
    path,
};

pub use files::SourceFile;

mod files;

/// Primary orchestrator and conductor of the analysis process.
///
/// This is main entrypoint into Glowy's logic and encapsulates all
/// implementation complexity. Library users should construct an instance using
/// [`Analyzer::new`] or [`Analyzer::from_go_mod`], configure any relevant
/// options (including adding source files with [`Analyzer::add_file`]), and
/// then execute the analysis with [`Analyzer::analyze`].
///
/// # Example Usage
///
/// ```
/// let mut analyzer = glowy::Analyzer::new("example.com/company-name/proj");
///
/// let file = glowy::SourceFile::read_from_disk("/main.go", "./proj/main.go")?;
/// analyzer.add_file(file);
///
/// let result = analyzer.analyze();
/// ```
pub struct Analyzer {
    module_base: String,
    files: Vec<SourceFile>,
}

impl Analyzer {
    /// Constructs a new bare instance of [`Analyzer`].
    ///
    /// The `module_base` argument is the module path of the Go module that will
    /// be analyzed, such as `example.com/company-name/proj`. Any inner packages
    /// within the module will be associated with paths relative to this value,
    /// allowing for imports like `import "example.com/company-name/proj/auth"`
    /// to be resolved.
    ///
    /// # Example Usage
    ///
    /// ```
    /// let mut analyzer = glowy::Analyzer::new("example.com/company-name/proj");
    /// ```
    ///
    /// # See Also
    ///
    /// It's often more convenient to use the [`Analyzer::from_go_mod`] utility
    /// instead, which is a helpful wrapper around this method.
    pub fn new(module_base: &str) -> Self {
        Self {
            module_base: module_base.to_owned(),
            files: Vec::new(),
        }
    }

    /// Constructs a new instance of [`Analyzer`] based on a `go.mod` file.
    ///
    /// This method is a wrapper around [`Analyzer::new`] that provides the
    /// convenience of extracting the base Go module path directly from a
    /// specified `go.mod` file. The file residing at the given path is opened
    /// in read-only mode and the module path is extracted from the first
    /// `module` directive per the [spec](https://go.dev/ref/mod).
    ///
    /// If no valid `module` directive is found, this method returns `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Any [`std::io::Error`] resulting from opening the file (such as it not
    /// existing) is returned as-is. The file is only read while no errors
    /// occur; if there is a read failure, no further attempts are performed and
    /// the method returns `Ok(None)` since no valid `module` directive was
    /// found.
    ///
    /// # Example Usage
    ///
    /// ```
    /// let mut analyzer = glowy::Analyzer::from_go_mod("./proj/go.mod")?;
    /// ```
    pub fn from_go_mod<P: AsRef<path::Path>>(path: P) -> io::Result<Option<Self>> {
        let file = fs::File::open(path)?;
        let reader = io::BufReader::new(file);
        let lines = reader.lines();

        for line in lines.map_while(Result::ok) {
            if let Some(base) = line.trim().strip_prefix("module ") {
                let base = base.split("//").next().unwrap().trim();

                // TODO: support alternative syntax per spec
                // "(" newline ModulePath newline ")"

                if !base.is_empty() {
                    return Ok(Some(Self::new(base)));
                }
            }
        }

        Ok(None)
    }

    /// Adds a new file to be analyzed.
    ///
    /// See [`SourceFile`] for more information on how to construct one.
    ///
    /// # Example Usage
    ///
    /// ```
    /// let file = glowy::SourceFile::read_from_disk("/main.go", "./proj/main.go")?;
    /// analyzer.add_file(file);
    /// ```
    pub fn add_file(&mut self, file: SourceFile) {
        self.files.push(file);
    }

    pub fn analyze(&self) {
        todo!()
    }
}
