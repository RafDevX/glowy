use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap, HashSet},
    env, fs,
    io::{self, BufRead},
    path,
};
#[cfg(feature = "parallelism")]
use std::{num, sync, thread};

use indexmap::IndexSet;
use parser::ast::SourceFileNode;
#[cfg(feature = "parallelism")]
use rayon::prelude::*;

use crate::{
    AnalysisConfig, DEFAULT_MAX_BUILD_TAG_DIMENSIONS, FullPackagePath, SourceFile,
    build_constraints::{self, BuildPermutation},
    context::{AnalysisContext, AnalysisStage},
    decls,
    errors::{AnalysisError, AnalysisErrorKind},
    labels::{Label, OwnedLabel, OwnedLabelCow},
    policy::{
        BlanketDirective, BlanketDirectiveKind, BlanketDirectiveTarget, BlanketDirectives,
        PackageBlanketDirectives,
    },
    taint,
};

// parallelizing parsing is not worth it at low total file size (rayon overhead)
const PARALLELIZE_PARSING_FROM: usize = 1 << 30; // 1 GiB

#[cfg(feature = "parallelism")]
static ANALYSIS_POOL: sync::LazyLock<rayon::ThreadPool> = sync::LazyLock::new(|| {
    // we try to leave two CPU cores free so other processes can run and the
    // system does not get too overwhelmed (all cores at 100% can go wrong).
    // note that this value is presently not configurable just because it would
    // mean re-generating this pool every analysis instance when the
    // configuration changed, which would require taking `&mut self` for
    // analysis, which is really not ideal
    let max_threads = thread::available_parallelism()
        .map(num::NonZero::get)
        .unwrap_or_default()
        .saturating_sub(2) // usually this means #cores - 2
        .max(2); // at least 2, or else there's no point to parallelism

    rayon::ThreadPoolBuilder::new()
        .thread_name(|i| format!("glowy-analysis-{i}"))
        .num_threads(max_threads)
        .build()
        .unwrap()
});

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
    /// Go module path base, such as `example.com/company-name/proj`.
    module_base: FullPackagePath,
    /// Files to analyze, always ordered by (virtual) file path.
    ///
    /// (Ordering reduces the need for switching context between packages).
    files: Vec<SourceFile>,
    /// Universal analysis configuration directives applying for all files.
    ///
    /// This is used instead of in-source function annotations, especially for
    /// functions not defined in this module (such as standard library ones).
    blanket_directives: BlanketDirectives,
    /// Whether to output more detailed status information during the analysis.
    verbose: bool,
    /// Whether `_test.go` files should be admitted into the analysis, mirroring
    /// `go build` (which excludes them) versus `go test` (which includes them).
    include_tests: bool,
    /// Maximum number of free build-tag dimensions to enumerate.
    ///
    /// See [`AnalysisConfig::max_build_tag_dimensions`] for semantics.
    max_build_tag_dimensions: usize,
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
    /// let analyzer = glowy::Analyzer::new("example.com/company-name/proj");
    /// ```
    ///
    /// # See Also
    ///
    /// It may often be more convenient to instead use the
    /// [`Analyzer::from_directory`] utility or [`Analyzer::from_go_mod`], which
    /// are helpful wrappers around this method.
    #[must_use]
    #[inline]
    pub fn new(module_base: &str) -> Self {
        Self {
            module_base: module_base.to_owned(),
            files: Vec::new(),
            blanket_directives: BlanketDirectives::new(),
            verbose: env::var("GLOWY_VERBOSE").is_ok(),
            include_tests: false,
            max_build_tag_dimensions: DEFAULT_MAX_BUILD_TAG_DIMENSIONS,
        }
    }

    /// Constructs a new instance of [`Analyzer`] from a Go module directory.
    ///
    /// This is the recommended constructor for most situations, where all
    /// Go source code files should be read from a unified directory on disk,
    /// the root of which contains a `go.mod` file that specifies the base
    /// module path (via a `module` directive).
    ///
    /// The specified directory is traversed recursively and all files with a
    /// `.go` extension are collected, except those with a `_test.go` suffix
    /// (unless the [`AnalysisConfig::include_tests`] option is enabled). Only
    /// real files and directories are considered: symlinks, for example, are
    /// ignored, since they could lead to cycles.
    ///
    /// Internally, this method uses [`Analyzer::from_go_mod`] and
    /// [`SourceFile::read_from_disk`], so their respective conditions apply.
    /// In particular, this method returns `Ok(None)` if no valid `module`
    /// directive was found in the `go.mod` file.
    ///
    /// Using this method to construct [`Analyzer`] brings the added advantage
    /// of [`Analyzer::ingest_config_file`] being automatically invoked if a
    /// `glowy.toml` configuration file is found in the project root. However,
    /// this is only possible if that method is available, i.e., if Cargo
    /// feature `toml-config` is enabled.
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
    #[inline]
    pub fn from_directory<P: AsRef<path::Path>>(path: P) -> io::Result<Option<Self>> {
        let Some(mut analyzer) = Self::from_go_mod(path.as_ref().join("go.mod"))? else {
            return Ok(None);
        };

        #[cfg(feature = "toml-config")]
        {
            // checking if the file exists ourselves could lead to strange race
            // conditions, so we just try it and see if it fails
            match analyzer.ingest_config_file(path.as_ref().join("glowy.toml")) {
                Ok(_) => {} // great
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    // no such file, so we just ignore this (don't report error)
                }
                Err(err) => return Err(err), // something else; report
            }
        }

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
    #[inline]
    pub fn from_go_mod<P: AsRef<path::Path>>(path: P) -> io::Result<Option<Self>> {
        let file = fs::File::open(path)?;
        let reader = io::BufReader::new(file);
        let lines = reader.lines().map_while(Result::ok);

        let mut in_block = false;

        for line in lines {
            let line = line
                .split_once("//")
                .map_or(line.as_str(), |(before, _)| before)
                .trim();

            // we accept either the simplified form `module ModulePath`,
            // or the block form `module ( \n ModulePath \n )`

            let candidate = if in_block {
                match line {
                    "" => continue, // skip empty line
                    ")" => {
                        // in normal circumstances this is usually unreachable,
                        // since the module path will already have been caught
                        // by the arm below in the previous line and this func
                        // will have returned. this is fine, we already assume
                        // that the input under analysis compiles, so it is ok
                        // to not check for the closing `)`... this arm should
                        // then only fire if somehow this go.mod is invalid or
                        // somehow has a `module ( \n NotValidModulePath \n )`
                        // block before the real `module ( \n ModulePath \n )`
                        // block (in which case we just exit this one for now)
                        in_block = false;

                        continue;
                    }
                    base => base,
                }
            } else {
                let Some(rest) = line.strip_prefix("module ").map(str::trim) else {
                    // not the module line
                    continue;
                };

                if rest == "(" {
                    in_block = true;

                    continue;
                }

                rest
            };

            if valid_module_path(candidate) {
                return Ok(Some(Self::new(candidate)));
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

            #[expect(
                clippy::filetype_is_file,
                reason = "Symlinks currently unsupported (could lead to cycles)"
            )]
            if file_type.is_dir() {
                self.add_directory_recurs(
                    virtual_path.as_ref().join(entry.file_name()),
                    entry.path(),
                )?;
            } else if file_type.is_file() {
                let file_real_path = entry.path();

                if file_real_path.extension().is_none_or(|ext| ext != "go") {
                    continue;
                }

                let file_name = entry.file_name();

                if !self.include_tests
                    && file_name
                        .to_str()
                        .is_some_and(|name| name.ends_with("_test.go"))
                {
                    continue;
                }

                let file = SourceFile::read_from_disk(
                    virtual_path.as_ref().join(file_name),
                    file_real_path,
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
    #[inline]
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
    #[inline]
    pub fn file_contents<P: AsRef<path::Path>>(&self, virtual_path: P) -> Option<&str> {
        self.files
            .binary_search_by_key(&virtual_path.as_ref(), SourceFile::virtual_path)
            .ok()
            .map(|index| self.files[index].contents())
    }

    /// Consumes and applies configuration options from a TOML file on disk.
    ///
    /// This utility method reads and parses a given TOML-formatted file into
    /// a structured [`AnalysisConfig`] object, subsequently passing it to
    /// [`Analyzer::ingest_structured_config`] so that its defined options may
    /// be applied.
    ///
    /// If ingestion is successful, `Ok(Ok(()))` is returned.
    ///
    /// Note that this method is only available if the Cargo feature
    /// `toml-config` is enabled.
    ///
    /// # Errors
    ///
    /// Any [`std::io::Error`] encountered while opening and reading the
    /// specified file is returned as-is, enclosed in a top-level [`Err`]
    /// variant. If no such error occurs, [`Ok`] is returned, containing a
    /// second-level [`Result`], which may encapsulate a TOML deserialization
    /// error as `Ok(Err)`.
    ///
    /// # See Also
    ///
    /// It may not be necessary to use this method directly, as if it is
    /// available, it is automatically invoked by [`Analyzer::from_directory`]
    /// if a `glowy.toml` file is found in the project root.
    #[cfg(feature = "toml-config")]
    #[inline]
    pub fn ingest_config_file<P: AsRef<path::Path>>(
        &mut self,
        path: P,
    ) -> io::Result<Result<(), toml::de::Error>> {
        let contents = fs::read_to_string(path)?;

        let config = match toml::from_str(&contents) {
            Ok(config) => config,
            Err(err) => return Ok(Err(err)),
        };

        self.ingest_structured_config(config);

        Ok(Ok(()))
    }

    /// Consumes and applies a unified structured analysis configuration object.
    ///
    /// This utility method allows invokers to easily configure the analysis by
    /// providing a standardized collection of configuration options and other
    /// customizable values. Each method invocation either merges with or fully
    /// overwrites previously set values, depending on the option, so a single
    /// invocation is recommended. See [`AnalysisConfig`] for which options are
    /// accepted.
    ///
    /// # Example Usage
    ///
    /// ```
    /// let mut analyzer = glowy::Analyzer::new("example.com/company-name/proj");
    ///
    /// let config = glowy::AnalysisConfig {
    ///     // change some fields here
    ///     // field1: value1,
    ///     // field2: value2,
    ///     ..Default::default()
    /// };
    ///
    /// analyzer.ingest_structured_config(config);
    /// ```
    ///
    /// # See Also
    ///
    /// It is often more convenient to specify per-project configuration by
    /// means of a TOML file. If Cargo feature `toml-config` is enabled, this
    /// library makes available the method [`Analyzer::ingest_config_file`],
    /// which automatically reads and parses such a file before invoking this
    /// present function under the hood.
    ///
    /// Note that if [`Analyzer::ingest_config_file`] is available, it is
    /// automatically invoked by [`Analyzer::from_directory`] if a `glowy.toml`
    /// file is found in the project root.
    #[inline]
    pub fn ingest_structured_config(&mut self, config: AnalysisConfig) {
        if !self.verbose {
            // never downgrade verbosity: if envvar is set, we never want it to
            // be overridden by e.g. a config file
            self.verbose = config.verbose;
        }

        self.include_tests = config.include_tests;
        self.max_build_tag_dimensions = config.max_build_tag_dimensions;

        let blanket_directives = config
            .sources
            .into_iter()
            .map(|(target, tags)| (BlanketDirectiveKind::Source, target, tags))
            .chain(
                config
                    .allow_sinks
                    .into_iter()
                    .map(|(target, tags)| (BlanketDirectiveKind::AllowSink, target, tags)),
            )
            .chain(
                config
                    .deny_sinks
                    .into_iter()
                    .map(|(target, tags)| (BlanketDirectiveKind::DenySink, target, tags)),
            );

        for (kind, target, tags) in blanket_directives {
            // we use add_blanket_directive directly to avoid conversion to
            // Label and then back to OwnedLabel (preventing unnecessary
            // allocations that would happen with add_blanket_source/sink)
            self.add_blanket_directive(kind, target, OwnedLabel::from(tags));
        }
    }

    fn add_blanket_directive<'c1: 'c2, 'c2>(
        &mut self,
        kind: BlanketDirectiveKind,
        target: BlanketDirectiveTarget,
        label: impl Into<OwnedLabelCow<'c1, 'c2>>,
    ) {
        let BlanketDirectiveTarget {
            package_path,
            type_name,
            member_name,
            arg_index,
        } = target;

        let directive = BlanketDirective::new(kind, arg_index, label);

        self.blanket_directives
            .entry(package_path)
            .or_default()
            .push(type_name, member_name, directive);
    }

    /// Universally registers a symbol or a method as an information source.
    ///
    /// This instructs the analyzer to always consider all calls to the given
    /// function or method as yielding the provided [`Label`], in addition to
    /// what is already otherwise derived from the function. If the specified
    /// symbol is not a function nor a method (i.e., if it is a variable or a
    /// constant), all accesses to it will analogously yield the provided
    /// [`Label`].
    ///
    /// The package path (`package_path`) is expected to be a well-formed,
    /// fully qualified Go package path of where the member is accessible,
    /// and `member_name` its declared symbol or method name.
    ///
    /// Each invocation to this function extends the blanket directives
    /// associated with the member path, meaning that previous versions are
    /// not overwritten. For sources, labels accumulate (union), so two source
    /// registrations for `{a}` and `{b}` are effectively equivalent to one
    /// registration for `{a, b}`.
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::labels::Label;
    /// #
    /// let mut analyzer = glowy::Analyzer::new("example.com/company-name/proj");
    ///
    /// analyzer.add_blanket_source(
    ///     "example.com/company-name/proj/sub",
    ///     None::<String>,
    ///     "SomeFunc",
    ///     &Label::from_tags(&["secret"]),
    /// );
    /// ```
    #[inline]
    pub fn add_blanket_source<'f>(
        &mut self,
        package_path: impl Into<Cow<'f, str>>,
        type_name: Option<impl Into<Cow<'f, str>>>,
        member_name: impl Into<Cow<'f, str>>,
        label: &Label<'_>,
    ) {
        let target = BlanketDirectiveTarget::new(
            package_path.into(),
            type_name.map(Into::into),
            member_name.into(),
            None, // argument targeting is meaningless for sources
        );

        self.add_blanket_directive(BlanketDirectiveKind::Source, target, label);
    }

    /// Universally registers a function as an information sink.
    ///
    /// This instructs the analyzer to always consider calls to the given
    /// function as only accepting the provided [`Label`] (for confidentiality,
    /// if `allow` is `true`) or as never accepting any overlap with the
    /// provided [`Label`] (for integrity, if `allow` is `false`).
    ///
    /// The `target` argument identifies which symbol or method (and,
    /// optionally, which specific function/method argument position) this sink
    /// applies to. It can be constructed manually or derived from a [`String`].
    ///
    /// Each invocation to this function extends the blanket directives
    /// associated with the target, meaning that previous versions are not
    /// overwritten. For sinks, each invocation defines an independent policy
    /// check, so two sink registrations for `{a}` and `{b}` are treated
    /// separately, and call arguments must satisfy both of them.
    ///
    /// # Example Usage
    ///
    /// ```
    /// # use glowy::{labels::Label, policy::BlanketDirectiveTarget};
    /// #
    /// let mut analyzer = glowy::Analyzer::new("example.com/company-name/proj");
    ///
    /// // applies to every argument passed to `SomeFunc`
    /// analyzer.add_blanket_sink(
    ///     BlanketDirectiveTarget::new(
    ///         "example.com/company-name/proj/sub",
    ///         None::<String>,
    ///         "SomeFunc",
    ///         None,
    ///     ),
    ///     false,
    ///     &Label::from_tags(&["untrusted"]),
    /// );
    ///
    /// // applies only to the second argument of `WriteFile`
    /// analyzer.add_blanket_sink(
    ///     BlanketDirectiveTarget::new("os", None::<String>, "WriteFile", Some(1)),
    ///     false,
    ///     &Label::from_tags(&["untrusted"]),
    /// );
    /// ```
    #[inline]
    pub fn add_blanket_sink(
        &mut self,
        target: BlanketDirectiveTarget,
        allow: bool,
        label: &Label<'_>,
    ) {
        let variant = if allow {
            BlanketDirectiveKind::AllowSink
        } else {
            BlanketDirectiveKind::DenySink
        };

        self.add_blanket_directive(variant, target, label);
    }

    fn has_blanket_enforcement_checks(&self) -> bool {
        self.blanket_directives
            .values()
            .flat_map(PackageBlanketDirectives::iter)
            .map(BlanketDirective::kind)
            .any(|kind| {
                matches!(
                    kind,
                    BlanketDirectiveKind::AllowSink | BlanketDirectiveKind::DenySink
                )
            })
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
    #[expect(
        clippy::missing_inline_in_public_items,
        reason = "Main entrypoint method"
    )]
    pub fn analyze(&self) -> Result<(), Vec<AnalysisError<'_>>> {
        let parsed = self.parse_files()?;

        if self.verbose {
            println!("Finished parsing {} file(s)", parsed.len());
        }

        let build_permutations = build_constraints::enumerate_build_permutations(
            &parsed,
            // the enumerator aborts early if it expects to exceed this limit
            self.max_build_tag_dimensions,
        );

        let build_permutations = match build_permutations {
            Ok(build_permutations) => build_permutations,
            Err(mentioned) => {
                return Err(vec![AnalysisError {
                    file: path::Path::new("/main.go"), // should never be used
                    kind: AnalysisErrorKind::TooManyBuildTagDimensions {
                        limit: self.max_build_tag_dimensions,
                        found: mentioned,
                    },
                }]);
            }
        };

        if build_permutations.is_empty() {
            return Err(vec![AnalysisError {
                file: path::Path::new("/main.go"), // should never be used
                kind: AnalysisErrorKind::NoRegisteredFiles,
            }]);
        }

        // ilog10 cannot panic here since we already checked that len > 0 (is_empty)
        let width = 1 + build_permutations.len().ilog10() as usize;

        if self.verbose {
            if build_permutations.len() > 1 {
                list_build_permutations(&build_permutations, width);
            }

            for path in parsed.keys() {
                if !build_permutations
                    .iter()
                    .map(|perm| &perm.admitted)
                    .any(|admitted| admitted.contains(path))
                {
                    println!(
                        "Ignoring file `{}` (not admitted to any build permutation)",
                        path.display()
                    );
                }
            }
        }

        let all_errors: IndexSet<_> =
            if cfg!(feature = "parallelism") && build_permutations.len() > 1 {
                // this looks a bit strange, but it means we can avoid all the
                // rayon parallelism overhead when there is only one singular
                // permutation to process, even if the `parallelism` cargo
                // feature is enabled, since it'd be a waste

                #[cfg(feature = "parallelism")]
                {
                    ANALYSIS_POOL.install(|| {
                        build_permutations
                            .par_iter()
                            .enumerate()
                            .flat_map_iter(|(index, permutation)| {
                                self.process_permutation(
                                    permutation,
                                    index,
                                    width,
                                    build_permutations.len(),
                                    &parsed,
                                )
                            })
                            .collect()
                    })
                }

                #[cfg(not(feature = "parallelism"))]
                IndexSet::new()
            } else {
                build_permutations
                    .iter()
                    .enumerate()
                    .flat_map(|(index, permutation)| {
                        self.process_permutation(
                            permutation,
                            index,
                            width,
                            build_permutations.len(),
                            &parsed,
                        )
                    })
                    .collect()
            };

        if self.verbose {
            println!(
                "Analysis is complete; detected a total of {} unique error(s)",
                all_errors.len()
            );
        }

        if all_errors.is_empty() {
            Ok(())
        } else {
            Err(all_errors.into_iter().collect())
        }
    }

    fn parse_files(
        &self,
    ) -> Result<BTreeMap<&path::Path, SourceFileNode<'_>>, Vec<AnalysisError<'_>>> {
        if self.files.is_empty() {
            return Err(vec![AnalysisError {
                file: path::Path::new("/main.go"), // should never be used
                kind: AnalysisErrorKind::NoRegisteredFiles,
            }]);
        }

        let mut parsed = BTreeMap::new();
        let mut parse_errors = vec![];

        macro_rules! process_results {
            ($results:expr) => {
                for (virtual_path, result) in $results {
                    match result {
                        Ok(ast) => {
                            if parsed.insert(virtual_path, ast).is_some() {
                                parse_errors.push(AnalysisError {
                                    file: virtual_path,
                                    kind: AnalysisErrorKind::DuplicateVirtualFilePath,
                                });
                            }
                        }
                        Err(err) => parse_errors.push(AnalysisError {
                            file: virtual_path,
                            kind: err.into(),
                        }),
                    }
                }
            };
        }

        let total_file_size: usize = self
            .files
            .iter()
            .map(SourceFile::contents)
            .map(str::len)
            .sum();

        if self.verbose {
            println!(
                "Parsing {} Go file(s) corresponding to a total of {total_file_size} bytes",
                self.files.len()
            );
        }

        // this looks a bit strange, but it means we can avoid all the rayon
        // parallelism overhead when there is not that much to parse, even if
        // the `parallelism` cargo feature is enabled, since it'd be a waste.
        // in particular, we cannot do `let results = if cfg! ...` because
        // `results` has different types depending on the branch (we would have
        // to collect on the sequential branch, but that allocation is wasteful)
        if cfg!(feature = "parallelism") && total_file_size >= PARALLELIZE_PARSING_FROM {
            #[cfg(feature = "parallelism")]
            {
                let results: Vec<_> = self
                    .files
                    .par_iter()
                    .map(|file| (file.virtual_path(), file.contents()))
                    .map(|(virtual_path, contents)| (virtual_path, parser::parse(contents)))
                    .collect(); // necessary to go from a rayon iter to a normal iter

                process_results!(results)
            }
        } else {
            let results = self
                .files
                .iter()
                .map(|file| (file.virtual_path(), file.contents()))
                .map(|(virtual_path, contents)| (virtual_path, parser::parse(contents)));

            process_results!(results)
        }

        if parse_errors.is_empty() {
            Ok(parsed)
        } else {
            Err(parse_errors)
        }
    }

    fn process_permutation<'a>(
        &'a self,
        permutation: &BuildPermutation<'a>,
        index: usize,
        width: usize,
        total_permutations: usize,
        parsed: &BTreeMap<&'a path::Path, SourceFileNode<'a>>,
    ) -> Vec<AnalysisError<'a>> {
        let verbose_prefix = if self.verbose && total_permutations > 1 {
            let prefix = format!("[#{:0>width$}/{}] ", index + 1, total_permutations);

            println!(
                "{prefix}Running analysis for build permutation {} ({} file(s))",
                permutation
                    .tag_sets
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" / "),
                permutation.admitted.len(),
            );

            Cow::Owned(prefix)
        } else {
            Cow::Borrowed("")
        };

        let admitted_asts: Vec<_> = parsed
            .iter()
            .filter(|(path, _)| permutation.admitted.contains(*path))
            .map(|(path, ast)| (*path, ast))
            .collect();

        let errors = self.analyze_permutation(&admitted_asts, &verbose_prefix);

        if self.verbose && total_permutations > 1 {
            println!(
                "{verbose_prefix}Detected {} error(s) while analyzing this build permutation",
                errors.len()
            );
        }

        errors
    }

    fn analyze_permutation<'a>(
        &'a self,
        admitted_asts: &[(&'a path::Path, &SourceFileNode<'a>)],
        verbose_prefix: &str,
    ) -> Vec<AnalysisError<'a>> {
        let mut context = AnalysisContext::new(&self.blanket_directives);

        macro_rules! pass {
            ($visitor:path, $worklist:expr) => {{
                let worklist: Option<&HashSet<FullPackagePath>> = $worklist;

                context.symtab_mut().clear_all_package_progress();

                for (path, ast) in admitted_asts {
                    let package_path = compute_package_path(&self.module_base, path);

                    if worklist.is_some_and(|pkgs| !pkgs.contains(&package_path)) {
                        // if `worklist` is Some, only visit files whose package
                        // is included; skipping at the package level is safe
                        continue;
                    }

                    context.set_current_file(path);

                    $visitor(&mut context, ast, package_path);
                }
            }};
        }

        // Stage #1: RecordDeclarations (default for AnalysisContext)
        //     An initial pass through all files to find top-level declarations
        //     and record what symbols exist, since they can be referenced from
        //     anywhere in any order (even textually before their definition).
        //     This is also used to scaffold sub-module hierarchies and package
        //     scopes, as well as register top-level named types.

        pass!(decls::visit_source_file, None);

        // retry resolving type registry entries that were enqueued during the
        // per-file decl walk above because their target was not yet known
        context.types_mut().run_deferred_resolutions();

        if self.verbose {
            println!("{verbose_prefix}Finished Stage 1");
        }

        // Stage #2: StabilizeLabels
        //     Repeatedly visit symbols and assign them labels (per taint
        //     propagation) until all labels stabilize. This must be repeated
        //     to support, for example, mutually recursive functions.

        context.set_stage(AnalysisStage::StabilizeLabels);

        let mut prev_snapshot: Option<HashMap<_, _>> = None;

        // we use a package-level worklist to avoid visiting every package every
        // iteration, which can be a helpful optimization in large projects.
        // once a package has converged and there is no remaining way for it to
        // change, it can just be omitted from all subsequent worklists.
        // if this is set to None, it means that we have to visit everything
        let mut worklist: Option<HashSet<FullPackagePath>> = None;

        // u8 is fine because this number should never be very high (<10), but
        // even if we do somehow reach overflow (>255), it's not the end of the
        // world to "restart" the iteration index from 0 since this is only used
        // for outputting status reports in verbose mode
        let mut iteration_index = 0_u8;

        loop {
            pass!(taint::visit_source_file, worklist.as_ref());

            let snapshot = context.symtab().snapshot_per_package();

            let unstable: HashSet<FullPackagePath> = snapshot
                .iter()
                .filter(|&(pkg, current)| {
                    let Some(prev) = &prev_snapshot else {
                        // if this is the first pass, keep everything
                        return true;
                    };

                    // keep only packages that changed since the last iteration.
                    // note that we never care about packages not present in the
                    // current snapshot, since they presumably have already been
                    // filtered out in previous iterations, and so they will
                    // never be revisited (worklist only narrows, never widens)

                    prev.get(pkg) != Some(current)
                })
                .map(|(pkg, _)| pkg.clone())
                .collect();

            if unstable.is_empty() {
                // nothing relevant has changed since the last iteration, so we
                // have reached label convergence and can thus stop the loop
                break;
            }

            // we only keep packages that changed since the last iteration
            // (i.e., unstable) and their reverse transitive dependencies (i.e.,
            // all packages that import directly or indirectly an unstable
            // package), since no others could ever be affected anymore
            let next_worklist = context.reverse_transitive_dependencies(&unstable);

            prev_snapshot = Some(snapshot);
            iteration_index += 1;

            if self.verbose {
                println!(
                    "{verbose_prefix}Finished convergence iteration #{iteration_index} (Stage 2) \
                     - {} package(s) changed; next pass visits {}",
                    unstable.len(),
                    next_worklist.len(),
                );
            }

            worklist = Some(next_worklist);
        }

        if self.verbose {
            println!(
                "{verbose_prefix}Finished Stage 2 in {} iterations",
                iteration_index + 1 // count the one where nothing changed
            );
        }

        // Stage #3: EnforceSecurityPolicies
        //     A final pass through all files to find and report data flow
        //     violations, now that labels are final.

        context.set_stage(AnalysisStage::EnforceSecurityPolicies);

        pass!(taint::visit_source_file, None);

        if !self.has_blanket_enforcement_checks() && !context.saw_enforcement_checks() {
            context.report_error_at(
                path::Path::new("/main.go"), // should never be used
                AnalysisErrorKind::NoSecurityPolicy,
            );
        }

        if self.verbose {
            println!("{verbose_prefix}Finished Stage 3");
        }

        match Result::from(context) {
            Ok(()) => Vec::new(),
            Err(errs) => errs,
        }
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

fn list_build_permutations(permutations: &[BuildPermutation<'_>], width: usize) {
    println!(
        "Detected {} distinct build-constraint permutation(s):",
        permutations.len()
    );

    // suppress any always-on tags so the output highlights the dimensions that
    // actually distinguish permutations from each other in this listing
    let always_on = build_constraints::always_active_tags(permutations);

    for (i, perm) in permutations.iter().enumerate() {
        let filtered_tags = perm
            .tag_sets
            .iter()
            .map(|tags| {
                let tag_set = tags
                    .iter()
                    .filter(|tag| !always_on.contains(tag))
                    .collect::<Vec<_>>()
                    .join(", ");

                format!("[{tag_set}]")
            })
            .collect::<Vec<_>>()
            .join(" / ");

        println!(
            "\tPermutation #{:0>width$}: {} file(s) with tags = {filtered_tags}",
            i + 1,
            perm.admitted.len(),
        );
    }
}
