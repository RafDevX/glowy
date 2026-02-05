use std::{
    collections::BTreeMap,
    fs,
    io::{self, BufRead},
    path,
};

use crate::{
    FullPackagePath, SourceFile,
    context::{AnalysisContext, AnalysisStage},
    decls,
    errors::{AnalysisError, AnalysisErrorKind},
    taint,
};

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
/// ```no_run
/// let analyzer = glowy::Analyzer::from_directory("./proj")?.expect("module path");
///
/// let result = analyzer.analyze();
///
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct Analyzer {
    /// Go module path base, such as `example.com/company-name/proj`
    module_base: FullPackagePath,
    /// Files to analyze, always ordered by (virtual) file path
    /// (Ordering reduces the need for switching context between packages)
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
    /// It's often more convenient to instead use the
    /// [`Analyzer::from_directory`] utility or [`Analyzer::from_go_mod`], which
    /// are helpful wrappers around this method.
    #[must_use]
    pub fn new(module_base: &str) -> Self {
        Self {
            module_base: module_base.to_owned(),
            files: Vec::new(),
        }
    }

    /// Constructs a new instance of [`Analyzer`] from a Go module directory.
    ///
    /// This is the recommended constructor for most situations, where all
    /// Go source code files should be read from a unified directory on disk,
    /// the root of which contains a `go.mod` file that specifies the base
    /// module path (via a `module` directive).
    ///
    /// Internally, this method uses [`Analyzer::from_go_mod`] and
    /// [`SourceFile::read_from_disk`], so their respective conditions apply.
    /// In particular, this method returns `Ok(None)` if no valid `module`
    /// directive was found in the `go.mod` file.
    ///
    /// # Errors
    ///
    /// An [`std::io::Error`] is returned if any filesystem operation fails,
    /// including (but not limited to):
    ///     - if the specified path does not correspond to an (accessible)
    ///       directory;
    ///     - if no `go.mod` file exists or could be opened;
    ///     - if a file with `.go` extension could not be read or contains
    ///       invalid UTF-8 sequences.
    ///
    /// # Example Usage
    ///
    /// ```no_run
    /// let analyzer = glowy::Analyzer::from_directory("./proj")?.expect("module path");
    ///
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn from_directory<P: AsRef<path::Path>>(path: P) -> io::Result<Option<Self>> {
        let Some(mut analyzer) = Self::from_go_mod(path.as_ref().join("go.mod"))? else {
            return Ok(None);
        };

        analyzer.add_directory_recurs(path::Component::RootDir, path)?;

        Ok(Some(analyzer))
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
    /// ```no_run
    /// let analyzer = glowy::Analyzer::from_go_mod("./proj/go.mod")?;
    ///
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[allow(clippy::missing_panics_doc)] // unwrap is guaranteed safe here
    pub fn from_go_mod<P: AsRef<path::Path>>(path: P) -> io::Result<Option<Self>> {
        let file = fs::File::open(path)?;
        let reader = io::BufReader::new(file);
        let lines = reader.lines();

        for line in lines.map_while(Result::ok) {
            if let Some(base) = line.trim().strip_prefix("module ") {
                let base = base.split("//").next().unwrap().trim();

                // TODO: support alternative syntax per spec
                // "(" newline ModulePath newline ")"

                if valid_module_path(base) {
                    return Ok(Some(Self::new(base)));
                }
            }
        }

        Ok(None)
    }

    fn add_directory_recurs<V: AsRef<path::Path>, R: AsRef<path::Path>>(
        &mut self,
        virtual_path: V,
        real_path: R,
    ) -> io::Result<()> {
        for entry in fs::read_dir(real_path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;

            if file_type.is_dir() {
                self.add_directory_recurs(
                    virtual_path.as_ref().join(entry.file_name()),
                    entry.path(),
                )?;
            } else if file_type.is_file() {
                let real_path = entry.path();

                if real_path.extension().filter(|e| *e == "go").is_none() {
                    continue;
                }

                let file = SourceFile::read_from_disk(
                    virtual_path.as_ref().join(entry.file_name()),
                    real_path,
                )?;

                self.add_file(file);
            }
            // else: file is a symlink; ignore (unsupported)
        }

        Ok(())
    }

    /// Adds a new file to be analyzed.
    ///
    /// See [`SourceFile`] for more information on how to construct one.
    ///
    /// # Example Usage
    ///
    /// ```no_run
    /// let mut analyzer = glowy::Analyzer::new("example.com/company-name/proj");
    ///
    /// let file = glowy::SourceFile::read_from_disk("/main.go", "./proj/main.go")?;
    /// analyzer.add_file(file);
    ///
    /// # Ok::<(), std::io::Error>(())
    /// ```
    ///
    /// # See Also
    ///
    /// When applicable, prefer using [`Analyzer::from_directory`] rather than
    /// manually re-implementing its logic with direct invocations of this
    /// method.
    pub fn add_file(&mut self, file: SourceFile) {
        // find the right spot for the file to not break sorting order
        let index = self
            .files
            .partition_point(|x| x.virtual_path() <= file.virtual_path());

        self.files.insert(index, file);
    }

    /// Retrieves a reference to a registered file's source code contents.
    ///
    /// This method allows its invoker to access the contents under analysis for
    /// a specific file by specifying its virtual path, as long as the file has
    /// been previously registered to the analyzer via [`Analyzer::add_file`] or
    /// another indirect method (such as the recommended
    /// [`Analyzer::from_directory`]).
    ///
    /// A return value of [`None`] indicates that no file was found matching the
    /// specified virtual path.
    ///
    /// # Example Usage
    ///
    /// ```
    /// # let mut analyzer = glowy::Analyzer::new("example.com/company-name/proj");
    /// # let file = glowy::SourceFile::new("/main.go", "package blueberry;");
    /// # analyzer.add_file(file);
    /// #
    /// let src = analyzer
    ///     .file_contents("/main.go")
    ///     .expect("Not yet registered");
    /// ```
    pub fn file_contents<P: AsRef<path::Path>>(&self, virtual_path: P) -> Option<&str> {
        self.files
            .binary_search_by_key(&virtual_path.as_ref(), SourceFile::virtual_path)
            .ok()
            .map(|index| self.files[index].contents())
    }

    /// Inspects the registered files for security policy violations.
    ///
    /// This encapsulates all principal logic in Glowy. All Go source code files
    /// registered via [`Analyzer::add_file`] (or [`Analyzer::from_directory`])
    /// are parsed and then analyzed for potential security vulnerabilities,
    /// according to this [`Analyzer`]'s configuration.
    ///
    /// A return value of `Ok(())` merely indicates that no problems were
    /// detected, but should not be misconstrued as an assurance that the
    /// program is categorically secure.
    ///
    /// # Errors
    ///
    /// If any parsing errors are reported, analysis is aborted and the
    /// corresponding [`AnalysisError`]s are returned immediately. Otherwise,
    /// Glowy proceeds with the analysis as intended, ultimately returning
    /// its conclusions.
    ///
    /// # Example Usage
    ///
    /// ```no_run
    /// let analyzer = glowy::Analyzer::from_directory("./proj")?.expect("module path");
    ///
    /// if let Err(errors) = analyzer.analyze() {
    ///     for error in errors {
    ///         // interpret results
    ///     }
    /// }
    ///
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn analyze(&self) -> Result<(), Vec<AnalysisError<'_>>> {
        let mut parsed = BTreeMap::new();
        let mut parse_errors = vec![];

        for file in &self.files {
            match parser::parse(file.contents()) {
                Ok(ast) => {
                    if parsed.insert(file.virtual_path(), ast).is_some() {
                        parse_errors.push(AnalysisError {
                            file: file.virtual_path(),
                            kind: AnalysisErrorKind::DuplicateVirtualFilePath,
                        });
                    }
                }
                Err(e) => parse_errors.push(AnalysisError {
                    file: file.virtual_path(),
                    kind: e.into(),
                }),
            }
        }

        if !parse_errors.is_empty() {
            return Err(parse_errors);
        }

        // Stage #1: RecordDeclarations (default for AnalysisContext)
        //     An initial pass through all files to find top-level declarations
        //     and record what symbols exist, since they can be referenced from
        //     anywhere in any order (even textually before their definition).
        //     This is also used to scaffold sub-module hierarchies and package
        //     scopes.

        let mut context = AnalysisContext::new();

        for (path, ast) in &parsed {
            context.set_current_file(path);

            let package_path = compute_package_path(&self.module_base, path);

            decls::visit_source_file(&mut context, ast, package_path);
        }

        // Stage #2: StabilizeLabels
        //     Repeatedly visit symbols and assign them labels (per taint
        //     propagation) until all labels stabilize. This must be repeated
        //     to support, for example, mutually recursive functions.

        context.set_stage(AnalysisStage::StabilizeLabels);

        // TODO: while ...

        context.symtab_mut().clear_all_package_progress();

        for (path, ast) in &parsed {
            context.set_current_file(path);

            let package_path = compute_package_path(&self.module_base, path);

            taint::visit_source_file(&mut context, ast, &package_path);
        }

        // Stage #3: EnforceSecurityPolicies
        //     A final pass through all files to find and report data flow
        //     violations, now that labels are final.

        context.set_stage(AnalysisStage::EnforceSecurityPolicies);

        // ----- TODO -----

        Result::from(context)
    }
}

// https://go.dev/ref/mod#go-mod-file-ident (not an exhaustive check)
fn valid_module_path(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate.is_ascii()
        && !candidate.starts_with('/')
        && !candidate.ends_with('/')
        && candidate
            .split('/')
            .all(|el| !el.is_empty() && !el.starts_with('.') && !el.ends_with('.'))
}

fn compute_package_path(module_base: &str, virtual_file_path: &path::Path) -> FullPackagePath {
    let dir_path = match virtual_file_path.parent() {
        Some(path) => path.to_string_lossy(),
        None => unreachable!("Malformed virtual file path = {virtual_file_path:?}"),
    };

    // trim for root, e.g. /main.go
    module_base.to_owned() + dir_path.trim_end_matches('/')
}
