use std::{
    borrow::Cow,
    fmt, fs, io,
    path::{Path, PathBuf},
    process,
    time::Instant,
};

use annotate_snippets::AnnotationKind;
use clap::Parser;
use colored::{ColoredString, Colorize};
use glowy::{
    errors::{AnalysisError, AnalysisErrorCategory, AnalysisErrorKind},
    labels::{LabelBacktrace, LabelBacktraceKind},
};

#[cfg(not(debug_assertions))] // release mode
const DOCS_ROOT_URL: &str = "https://glowy.rso.pt/glowy";
#[cfg(debug_assertions)] // debug mode
const DOCS_ROOT_URL: &str = concat!(
    "file://",
    env!("CARGO_MANIFEST_DIR"),
    "/target/doc/",
    env!("CARGO_CRATE_NAME")
);

fn main() {
    let config = Config::parse();

    let (_warnings, errors) = if config.multi_suites {
        analyze_multi_suites(&config.directory, config.time_analysis)
    } else if config.suite {
        analyze_suite(&config.directory, config.time_analysis)
    } else {
        analyze_single(&config.directory, config.time_analysis)
    };

    if errors > 0 {
        process::exit(2)
    }
}

fn analyze_single<P: AsRef<Path>>(path: P, time_analysis: bool) -> (usize, usize) {
    let analyzer = glowy::Analyzer::from_directory(path)
        .unwrap_or_else(|_| {
            fatal(
                "IO error occurred when reading the specified directory.",
                "Does a `go.mod` file exist?",
            )
        })
        .unwrap_or_else(|| {
            fatal(
                "Unknown module path.",
                "No `module` directive was found in the specified directory's `go.mod` file.",
            )
        });

    let start = Instant::now();

    let result = analyzer.analyze();

    if time_analysis {
        let elapsed = start.elapsed();

        println!(
            "{} {} {}\n",
            "@@@ Analysis duration:".bright_magenta().bold(),
            format!("{:?}", elapsed).blue().bold(),
            "@@@".bright_magenta().bold()
        )
    }

    match result {
        Ok(_) => {
            println!("Analysis succeeded with no errors found!");

            (0, 0)
        }
        Err(errors) => {
            let renderer = annotate_snippets::Renderer::styled();

            let mut warning_count = 0;
            let mut error_count = 0;

            for error in errors {
                let category = error.kind.category();
                if error_category_to_level(category) == annotate_snippets::Level::ERROR {
                    error_count += 1;
                } else {
                    warning_count += 1;
                }

                let group = error_to_group(&error, &analyzer);
                let report = &[group];

                anstream::eprintln!("{}", renderer.render(report));
            }

            (warning_count, error_count)
        }
    }
}

fn analyze_multi(mut modules: Vec<PathBuf>, time_analysis: bool) -> (usize, usize) {
    if modules.is_empty() {
        fatal(
            "No directories found in the specified modules directory.",
            "Is the path provided correct?",
        )
    }

    modules.sort_unstable();

    let mut results = vec![];

    let width = 1 + modules.len() / 10;
    let start = Instant::now();

    for (i, module) in modules.into_iter().enumerate() {
        let title = ColoredGroup::new()
            .push(format!("#{:0>width$} - ", i + 1).cyan())
            .push("Module @ ".blue())
            .push(module.to_string_lossy().purple());
        println!("{}", build_header(title));

        results.push((
            module.to_string_lossy().into_owned(),
            analyze_single(module, time_analysis),
        ));

        println!("\n");
    }

    println!("{}", build_header("SUMMARY".cyan()));

    if time_analysis {
        let elapsed = start.elapsed();

        println!(
            "{} {} {} {}\n",
            "@@@@@@@@@@ TOTAL ANALYSIS DURATION:"
                .bright_magenta()
                .bold(),
            format!("{:?}", elapsed).blue().bold(),
            "(all modules)".bright_magenta().italic(),
            "@@@@@@@@@@".bright_magenta().bold()
        )
    }

    let mut n_failed = 0;
    let mut n_warned = 0;
    let mut n_passed = 0;

    for (i, (module, (warnings, errors))) in results.iter().enumerate() {
        let (emoji, label) = if *errors > 0 {
            n_failed += 1;

            ("❌", "FAIL".bright_red())
        } else if *warnings > 0 {
            n_warned += 1;

            ("⚠️", "WARN".yellow())
        } else {
            n_passed += 1;

            ("✅", "PASS".green())
        };

        println!(
            "\t- {} [{}] #{:0>width$} - {} {}",
            emoji,
            label,
            i + 1,
            module.bold(),
            format!("({errors} errors, {warnings} warnings)").italic()
        );
    }

    let aggregate = results
        .iter()
        .map(|(_, t)| t)
        .copied()
        .reduce(|(acc_w, acc_e), (w, e)| (acc_w + w, acc_e + e))
        .unwrap_or((0, 0));

    println!(
        "\n{} {} failed, {} warned, {} passed {}",
        "TOTAL:".bold().blue(),
        n_failed.to_string().bright_red(),
        n_warned.to_string().yellow(),
        n_passed.to_string().green(),
        format!(
            "(total {} errors, {} warnings)",
            aggregate.1.to_string().bright_red(),
            aggregate.0.to_string().yellow()
        )
        .italic()
    );

    aggregate
}

fn analyze_suite<P: AsRef<Path>>(path: P, time_analysis: bool) -> (usize, usize) {
    let modules = list_dirs_in_dir(path).collect();

    analyze_multi(modules, time_analysis)
}

fn analyze_multi_suites<P: AsRef<Path>>(path: P, time_analysis: bool) -> (usize, usize) {
    let mut modules = vec![];

    for suite in list_dirs_in_dir(path) {
        let suite_modules = list_dirs_in_dir(suite);

        modules.extend(suite_modules);
    }

    analyze_multi(modules, time_analysis)
}

fn list_dirs_in_dir<P: AsRef<Path>>(path: P) -> impl Iterator<Item = PathBuf> {
    fs::read_dir(path)
        .and_then(Iterator::collect::<Result<Vec<_>, io::Error>>)
        .unwrap_or_else(|_| {
            fatal(
                "IO error occurred when reading the specified directory.",
                "Does the path provided exist?",
            )
        })
        .into_iter()
        .filter(|entry| entry.file_type().as_ref().is_ok_and(fs::FileType::is_dir))
        .map(|entry| entry.path())
}

#[derive(clap::Parser)]
#[command(version, about)]
struct Config {
    /// Path to a directory containing a Go module, including a `go.mod` file.
    directory: PathBuf,
    // ^ positional because no #[arg]
    /// Analyze a directory of directories with Go modules, vs. just one module.
    #[arg(long, alias("multi"))]
    suite: bool,
    /// Analyze multiple suites (directories of directories with Go modules).
    #[arg(long)]
    multi_suites: bool,
    /// Repord elapsed time for the entire analysis process (including parsing).
    #[arg(long)]
    time_analysis: bool,
}

// group can just be format! ?
struct ColoredGroup {
    items: Vec<ColoredString>,
}

impl ColoredGroup {
    fn new() -> Self {
        Self { items: vec![] }
    }

    fn push<S: Into<ColoredString>>(mut self, item: S) -> Self {
        self.items.push(item.into());

        self
    }

    fn space(self) -> Self {
        self.push(" ")
    }

    fn newline(self) -> Self {
        self.push("\n")
    }

    fn absorb<F: Fn(ColoredString) -> ColoredString>(
        mut self,
        other: Self,
        transformation: Option<F>,
    ) -> Self {
        for item in other.items {
            let transformed = if let Some(f) = &transformation {
                f(item)
            } else {
                item
            };

            self.items.push(transformed)
        }

        self
    }

    fn len(&self) -> usize {
        self.items.iter().map(|s| s.len()).sum()
    }
}

impl fmt::Display for ColoredGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for item in &self.items {
            item.fmt(f)?
        }

        Ok(())
    }
}

impl<T: Into<ColoredString>> From<T> for ColoredGroup {
    fn from(s: T) -> Self {
        Self {
            items: vec![s.into()],
        }
    }
}

fn fatal(msg: &str, hint: &str) -> ! {
    eprintln!(
        "{} {}\n\n\t{}",
        "[FATAL]".bold().bright_red(),
        msg.bright_red(),
        hint.italic().cyan()
    );
    process::exit(1)
}

fn build_header<T: Into<ColoredGroup>>(title: T) -> ColoredGroup {
    let title = title.into();
    let width = title.len() + 2 * 6;

    ColoredGroup::new()
        .push("#".repeat(width).yellow())
        .newline()
        .push("#".repeat(5).yellow())
        .space()
        .absorb(title, Some(ColoredString::bold))
        .space()
        .push("#".repeat(5).yellow())
        .newline()
        .push("#".repeat(width).yellow())
        .newline()
}

struct SnippetBuilder<'a> {
    analyzer: &'a glowy::Analyzer,
    home: &'a Path, // default file
}

impl<'a> SnippetBuilder<'a> {
    fn new(analyzer: &'a glowy::Analyzer, home: &'a Path) -> Self {
        Self { analyzer, home }
    }

    fn home(&self) -> Cow<'_, str> {
        self.home.to_string_lossy()
    }

    fn snippet(&self) -> StructuredSnippet<'a> {
        self.snippet_for(self.home)
    }

    fn snippet_for(&self, path: &'a Path) -> StructuredSnippet<'a> {
        let source = self
            .analyzer
            .file_contents(path)
            .expect("specified error file not registered");

        StructuredSnippet::new(path.to_string_lossy(), source)
    }

    fn eof(&self) -> parser::Location {
        self.eof_for(self.home)
    }

    // This method only exists because `annotate_snippets::Snippet` does not
    // make its source field public, meaning we cannot calculate EOF without
    // access to the analyzer's file repository.
    // Note that this might return an empty range if the source file is empty.
    fn eof_for(&self, path: &'a Path) -> parser::Location {
        let source = self
            .analyzer
            .file_contents(path)
            .expect("specified error file not registered");

        source.len().saturating_sub(1)..source.len()
    }
}

// we use an intermediate representation (strongly typed) to ensure all errors
// have the same fields defined and none is ever forgotten/missed
#[derive(Debug, Clone)]
struct StructuredErrorInfo<'a> {
    title: Cow<'a, str>,
    code: Cow<'a, str>,
    snippets: Vec<StructuredSnippet<'a>>,
    help: Option<&'a str>,
}

// intermediate representation (vs. Snippet directly) so we can perform some
// minor manipulation before rendering (Snippet does not expose its data)
// [we need this to be able to collapse snippets]
#[derive(Debug, Clone)]
struct StructuredSnippet<'a> {
    path: Cow<'a, str>,
    source: Cow<'a, str>,
    annotations: Vec<StructuredAnnotation<'a>>, // deduplicated
}

impl<'a> StructuredSnippet<'a> {
    fn new(path: impl Into<Cow<'a, str>>, source: impl Into<Cow<'a, str>>) -> Self {
        Self {
            path: path.into(),
            source: source.into(),
            annotations: vec![],
        }
    }

    fn annotate(mut self, annotation: StructuredAnnotation<'a>) -> Self {
        if !self.annotations.contains(&annotation) {
            self.annotations.push(annotation);
        }

        self
    }

    fn extend(mut self, annotations: impl IntoIterator<Item = StructuredAnnotation<'a>>) -> Self {
        for annotation in annotations {
            self = self.annotate(annotation);
        }

        self
    }
}

impl<'a> From<StructuredSnippet<'a>>
    for annotate_snippets::Snippet<'a, annotate_snippets::Annotation<'a>>
{
    fn from(snippet: StructuredSnippet<'a>) -> Self {
        annotate_snippets::Snippet::source(snippet.source)
            .path(snippet.path)
            .annotations(snippet.annotations.into_iter().map(Into::into))
    }
}

// intermediate representation (vs. Annotation directly) so we can perform some
// minor manipulation before rendering (Annotation does not expose its data)
// [we need this to be able to deduplicate annotations, since no PartialEq impl]
#[derive(PartialEq, Debug, Clone)]
struct StructuredAnnotation<'a> {
    kind: AnnotationKind,
    location: parser::Location,
    label: Option<Cow<'a, str>>,
    highlight_source: bool,
}

impl<'a> StructuredAnnotation<'a> {
    fn new(kind: AnnotationKind, location: parser::Location) -> Self {
        Self {
            kind,
            location,
            label: None,
            highlight_source: false,
        }
    }

    fn primary(location: parser::Location) -> Self {
        Self::new(AnnotationKind::Primary, location)
    }

    fn context(location: parser::Location) -> Self {
        Self::new(AnnotationKind::Context, location)
    }

    fn label(mut self, label: impl Into<Cow<'a, str>>) -> Self {
        self.label = Some(label.into());

        self
    }
}

impl<'a> From<StructuredAnnotation<'a>> for annotate_snippets::Annotation<'a> {
    fn from(annotation: StructuredAnnotation<'a>) -> Self {
        annotation
            .kind
            .span(annotation.location)
            .label(annotation.label)
            .highlight_source(annotation.highlight_source)
    }
}

fn error_to_group<'a>(
    error: &'a AnalysisError<'a>,
    analyzer: &'a glowy::Analyzer,
) -> annotate_snippets::Group<'a> {
    let level = error_category_to_level(error.kind.category());

    let builder = SnippetBuilder::new(analyzer, error.file);

    let info = get_structured_error_info(&error.kind, &builder);

    let help_msg = info
        .help
        .map(|txt| annotate_snippets::Level::HELP.message(txt))
        .map(annotate_snippets::Element::from);

    let elements = collapse_snippets(info.snippets)
        .into_iter()
        .map(annotate_snippets::Snippet::from)
        .map(annotate_snippets::Element::from);

    level
        .primary_title(info.title)
        .id(info.code)
        .id_url(format!(
            "{}/errors/enum.AnalysisErrorKind.html#variant.{}",
            DOCS_ROOT_URL,
            format!("{:?}", error.kind)
                .split(|ch: char| !ch.is_alphabetic())
                .next()
                .unwrap()
        ))
        .elements(elements.chain(help_msg))
}

fn get_structured_error_info<'a>(
    kind: &'a AnalysisErrorKind<'a>,
    builder: &SnippetBuilder<'a>,
) -> StructuredErrorInfo<'a> {
    match kind {
        AnalysisErrorKind::Parsing(inner) => {
            let diagnostics = parser::Diagnostics::diagnostics(inner);
            let location = if let Some(ctx) = diagnostics.context {
                ctx.location()
            } else {
                builder.eof()
            };

            StructuredErrorInfo {
                title: diagnostics.overview.into(),
                code: diagnostics.code.into(),
                snippets: vec![
                    builder.snippet().annotate(
                        StructuredAnnotation::primary(location).label(diagnostics.details),
                    ),
                ],
                help: None,
            }
        }

        AnalysisErrorKind::DuplicateVirtualFilePath => StructuredErrorInfo {
            title: format!("duplicate virtual file path `{}`", builder.home()).into(),
            code: "C001".into(),
            snippets: vec![],
            help: Some(
                "another file with this virtual path had already been registered to the analyzer",
            ),
        },

        AnalysisErrorKind::UnknownAnnotationDirective {
            directive,
            location,
        } => StructuredErrorInfo {
            title: format!("unknown Glowy annotation directive `{directive}`").into(),
            code: "V001".into(),
            snippets: vec![
                builder
                    .snippet()
                    .annotate(StructuredAnnotation::primary(location.clone())),
            ],
            help: Some("this directive may be unsupported by this version of the analyzer"),
        },

        AnalysisErrorKind::InsecureFlow { sink, backtrace } => {
            let (context, operand) = match sink.kind {
                glowy::SinkKind::Declaration => ("declaration", "the initialization value"),
                glowy::SinkKind::Call => ("function call", "an argument"),
                glowy::SinkKind::Send => ("send statement", "the value being sent"),
            };

            StructuredErrorInfo {
                title: format!("insecure data flow to sink in {context}").into(),
                code: format!("F{:0>3}", sink.kind as usize + 1).into(),
                snippets: label_backtrace_to_snippets(
                    backtrace,
                    Some(format!(
                        "sink has label {}, but {} has label {}",
                        sink.label,
                        operand,
                        backtrace.label()
                    )),
                    builder,
                ),
                help: Some("if this is expected behavior, consider adjusting the security policy"),
            }
        }
        AnalysisErrorKind::FalseAssertion {
            expected,
            found,
            location,
        } => StructuredErrorInfo {
            title: "expression label assertion is false".into(),
            code: "A001".into(),
            snippets: if let Some(backtrace) = found {
                label_backtrace_to_snippets(
                    backtrace,
                    Some(format!(
                        "assertion expects label {}, but found label {}",
                        expected,
                        backtrace.label()
                    )),
                    builder,
                )
            } else {
                vec![builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone()).label(format!(
                        "assertion expects label {}, but found Bottom (i.e., {})",
                        expected,
                        glowy::labels::Label::Bottom
                    )),
                )]
            },
            help: Some(
                "error reported because the expression label differed from the declared \
                 expectation",
            ),
        },

        AnalysisErrorKind::DistinctPackageName { previous, found } => StructuredErrorInfo {
            title: format!(
                "declared package name `{}` differs from previously found `{}`",
                found.content(),
                previous.content()
            )
            .into(),
            code: "G001".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(found.location().clone()).label(
                        "this package name does not match other files in the same directory",
                    ),
                ),
                builder.snippet_for(previous.file()).annotate(
                    StructuredAnnotation::context(previous.inner().location().clone())
                        .label("previously found this conflicting package name declaration"),
                ),
            ],
            help: Some("due to the incompatibility, the file was excluded from the analysis"),
        },
        AnalysisErrorKind::UnresolvableUnqualifiedImport { location } => StructuredErrorInfo {
            title: "could not resolve native qualifier for unknown package import".into(),
            code: "G002".into(),
            snippets: vec![
                builder
                    .snippet()
                    .annotate(StructuredAnnotation::primary(location.clone()).label(
                        "cannot determine native package name, as it has not been analyzed",
                    )),
            ],
            help: Some("consider manually specifying an import qualifier"),
        },
        AnalysisErrorKind::DuplicateImportQualifier { location } => StructuredErrorInfo {
            title: "duplicate import qualifier within the same file".into(),
            code: "G003".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("this illegally conflicts with a previous import declaration"),
                ),
            ],
            help: Some("consider changing one of the qualifiers"),
        },
        AnalysisErrorKind::IllegalRedeclaration { previous, found } => StructuredErrorInfo {
            title: "illegal symbol redeclaration within same scope".into(),
            code: "G004".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(found.location().clone())
                        .label("this declaration conflicts with a previous one"),
                ),
                builder.snippet_for(previous.file()).annotate(
                    StructuredAnnotation::context(previous.inner().location().clone())
                        .label("previously found this declaration"),
                ),
            ],
            help: Some("check if your code meets Go's strict criteria for valid redeclarations"),
        },
        AnalysisErrorKind::UnknownSymbol { found } => StructuredErrorInfo {
            title: "invalid access of unknown symbol".into(),
            code: "G005".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(found.location().clone())
                        .label("this operand name could not be resolved within the current scope"),
                ),
            ],
            help: Some("check if the operand name is spelled correctly"),
        },
        AnalysisErrorKind::UnknownQualifier { found } => StructuredErrorInfo {
            title: "invalid reference to unknown qualifier".into(),
            code: "G006".into(),
            snippets: vec![builder.snippet().annotate(
                StructuredAnnotation::primary(found.location().clone()).label(
                    "this qualifier does not match any import declaration within the current file",
                ),
            )],
            help: Some("check the file's import declarations"),
        },
        AnalysisErrorKind::UnexpectedReturn { location } => StructuredErrorInfo {
            title: "unexpected return statement outside a function definition".into(),
            code: "G007".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("this return statement is illegal outside a function context"),
                ),
            ],
            help: Some("fix the surrounding syntax to encapsulate the return in a function"),
        },
        AnalysisErrorKind::MismatchingReturnCardinality {
            expected,
            found,
            location,
        } => StructuredErrorInfo {
            title: "returned values cardinality differs from previous return statement".into(),
            code: "G008".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label(format!("expected {expected} value(s), but found {found}")),
                ),
            ],
            help: Some("ensure all of this function's return statements match the signature"),
        },
        AnalysisErrorKind::Unreachable { location } => StructuredErrorInfo {
            title: "unreachable statement found after a block-terminating statement".into(),
            code: "G009".into(),
            snippets: vec![builder.snippet().annotate(
                StructuredAnnotation::primary(location.clone()).label(
                    "this statement is unreachable since control flow is diverted before it",
                ),
            )],
            help: Some("consider moving the statement to run earlier in the block"),
        },
        AnalysisErrorKind::IllegalCallExpression { location } => StructuredErrorInfo {
            title: "illegal call expression".into(),
            code: "G010".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("the expression being invoked could not be resolved to a function"),
                ),
            ],
            help: Some("confirm that a function declaration was provided"),
        },
        AnalysisErrorKind::IncorrectCallCardinality {
            expected,
            found,
            location,
        } => StructuredErrorInfo {
            title: format!("expected {expected} arguments in function call, but found {found}")
                .into(),
            code: "G011".into(),
            snippets: vec![
                builder
                    .snippet()
                    .annotate(StructuredAnnotation::primary(location.clone()).label(
                        "incorrect call cardinality with regard to declared function arity",
                    )),
            ],
            help: Some("check that the number of arguments is correct"),
        },
        AnalysisErrorKind::UnexpectedBuiltInArgShape { location } => StructuredErrorInfo {
            title: "unexpected argument shape passed to built-in function".into(),
            code: "G012".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("argument has a type not supported by this Go built-in"),
                ),
            ],
            help: Some("check that the correct arguments were provided"),
        },
        AnalysisErrorKind::UnevenBindingDeclSpec {
            location,
            left,
            right,
        } => StructuredErrorInfo {
            title: "mismatching number of identifiers and expressions in binding declaration spec"
                .into(),
            code: "G013".into(),
            snippets: vec![builder.snippet().annotate(
                StructuredAnnotation::primary(location.clone()).label(format!(
                    "cannot assign {right} value(s) to {left} identifier(s)"
                )),
            )],
            help: Some("adjust one of the sides to match the other"),
        },
        AnalysisErrorKind::UnevenAssignment {
            location,
            left,
            right,
        } => StructuredErrorInfo {
            title: "mismatching number of left-values and expressions in binding declaration spec"
                .into(),
            code: "G014".into(),
            snippets: vec![builder.snippet().annotate(
                StructuredAnnotation::primary(location.clone()).label(format!(
                    "cannot assign {right} right-value(s) to {left} left-value(s)"
                )),
            )],
            help: Some("adjust one of the sides to match the other"),
        },
        AnalysisErrorKind::MultiComplexAssignment { location, num } => StructuredErrorInfo {
            title: "invalid complex assignment with more than one left-value".into(),
            code: "G015".into(),
            snippets: vec![builder.snippet().annotate(
                StructuredAnnotation::primary(location.clone()).label(format!(
                    "cannot perform a complex assignment on {num} left-values simultaneously"
                )),
            )],
            help: Some("consider using a simple assignment (e.g., `=` instead of `+=`)"),
        },
        AnalysisErrorKind::InvalidLeftValue { location } => StructuredErrorInfo {
            title: "illegal or unsupported expression used as a left-value for assignment".into(),
            code: "G016".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("this expression cannot be resolved to a valid left-value"),
                ),
            ],
            help: Some("check whether the specified left-value is correct"),
        },
        AnalysisErrorKind::ImmutableLeftValue { symbol } => StructuredErrorInfo {
            title: "immutable left-value in assignment".into(),
            code: "G017".into(),
            snippets: vec![builder.snippet().annotate(
                StructuredAnnotation::primary(symbol.location().clone()).label(format!(
                    "symbol `{}` is constant or unchangeable",
                    symbol.content()
                )),
            )],
            help: Some("check whether the specified left-value should be marked as immutable"),
        },
        AnalysisErrorKind::InvalidSelectionBase { location } => StructuredErrorInfo {
            title: "illegal or unsupported expression used as a selection base".into(),
            code: "G018".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("this expression cannot be resolved to a valid selection base"),
                ),
            ],
            help: Some("check whether the specified selection base is a struct"),
        },
        AnalysisErrorKind::InvalidIndexingBase { location } => StructuredErrorInfo {
            title: "illegal or unsupported expression used as an indexing base".into(),
            code: "G019".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("this expression cannot be resolved to a valid indexing base"),
                ),
            ],
            help: Some("check whether the specified selection base is an array/slice"),
        },
        AnalysisErrorKind::InvalidSlicingBase { location } => StructuredErrorInfo {
            title: "illegal or unsupported expression used as a slicing base".into(),
            code: "G020".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("this expression cannot be resolved to a valid slicing base"),
                ),
            ],
            help: Some("check whether the specified slicing base is a string/array/slice"),
        },
        AnalysisErrorKind::IllegalChannelExpression { location } => StructuredErrorInfo {
            title: "illegal or unsupported expression used as a channel in a send statement".into(),
            code: "G021".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("this expression cannot be resolved to a channel"),
                ),
            ],
            help: Some("check whether the specified expression is a channel"),
        },
        AnalysisErrorKind::GoNotCall { location } => StructuredErrorInfo {
            title: "illegal `go` statement with a non-call expression".into(),
            code: "G022".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("this expression cannot be resolved to a function call"),
                ),
            ],
            help: Some("check whether the specified expression is a function call"),
        },
        AnalysisErrorKind::IllegalSelectCase { location } => StructuredErrorInfo {
            title: "illegal case in `select` statement".into(),
            code: "G023".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("this is neither a send or a receive statement"),
                ),
            ],
            help: Some("cases in a `select` statement can only pertain to channel communications"),
        },
        AnalysisErrorKind::UnexpectedFallthrough { location } => StructuredErrorInfo {
            title: "unexpected fallthrough statement".into(),
            code: "G024".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("a fallthrough statement is illegal at this location"),
                ),
            ],
            help: Some("ensure the statement is at the end of an expression switch clause"),
        },
        AnalysisErrorKind::DuplicateStructFieldName { duplicate } => StructuredErrorInfo {
            title: "duplicate field name in struct literal expression".into(),
            code: "G025".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(duplicate.location().clone())
                        .label("another field with this name has already been specified"),
                ),
            ],
            help: Some("ensure there are no duplicate entries in the struct literal"),
        },
        AnalysisErrorKind::UnexpectedVoidExpression { location } => StructuredErrorInfo {
            title: "invalid void expression when a single value was expected".into(),
            code: "G026".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("this expression yields no value, but one value was expected"),
                ),
            ],
            help: Some("ensure the expression's value-arity is compatible with where it is used"),
        },
        AnalysisErrorKind::UnexpectedMultiValueExpression { location } => StructuredErrorInfo {
            title: "invalid multi-value expression when a single value was expected".into(),
            code: "G027".into(),
            snippets: vec![builder.snippet().annotate(
                StructuredAnnotation::primary(location.clone()).label(
                    "this expression yields multiple values, but only one value was expected",
                ),
            )],
            help: Some("ensure the expression's value-arity is compatible with where it is used"),
        },

        AnalysisErrorKind::GotoNotSupported { location } => StructuredErrorInfo {
            title: "unsupported `goto` statement was ignored".into(),
            code: "U001".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("this statement was not considered to affect control flow"),
                ),
            ],
            help: Some("this analyzer version does not support `goto` statements"),
        },
        AnalysisErrorKind::DeferNotDeferred { location } => StructuredErrorInfo {
            title: "unsupported `defer` statement was not deferred".into(),
            code: "U002".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("this expression was considered to execute immediately"),
                ),
            ],
            help: Some("this analyzer version does not support `defer` statements"),
        },
    }
}

fn error_category_to_level(category: AnalysisErrorCategory) -> annotate_snippets::Level<'static> {
    // TODO: pedantic flag

    match category {
        AnalysisErrorCategory::Misconfiguration
        | AnalysisErrorCategory::SecurityPolicyViolation => annotate_snippets::Level::ERROR,
        AnalysisErrorCategory::UnrecognizedFeature
        | AnalysisErrorCategory::InvalidGo
        | AnalysisErrorCategory::UnsupportedGo => annotate_snippets::Level::WARNING,
    }
}

fn label_backtrace_to_snippets<'a>(
    backtrace: &'a LabelBacktrace<'a>,
    root_label: Option<String>,
    builder: &SnippetBuilder<'a>,
) -> Vec<StructuredSnippet<'a>> {
    let (kind, label) = if let Some(label) = root_label {
        (AnnotationKind::Primary, label)
    } else {
        macro_rules! symbol {
            ($default:expr) => {
                if let Some(name) = backtrace.symbol() {
                    format!("symbol `{}`", name)
                } else {
                    $default.to_owned()
                }
            };
            () => {
                symbol!("symbol")
            };
        }

        let label = match backtrace.kind() {
            LabelBacktraceKind::ExplicitAnnotation => format!(
                "{} has been explicitly annotated with label {}",
                symbol!(),
                backtrace.label()
            ),
            LabelBacktraceKind::Assignment => format!(
                "{} has been assigned a tainted value, resulting in label {}",
                symbol!(),
                backtrace.label()
            ),
            LabelBacktraceKind::DeclarationInitialization => format!(
                "{} has been declared with initialization expression labeled {}",
                symbol!(),
                backtrace.label()
            ),
            LabelBacktraceKind::Expression => {
                format!("{} has label {}", symbol!("expression"), backtrace.label())
            }
            LabelBacktraceKind::Branch => {
                format!("execution branch has label {}", backtrace.label())
            }
            LabelBacktraceKind::Send => format!(
                "information sent into channel has label {}",
                backtrace.label()
            ),
            LabelBacktraceKind::Receive => format!(
                "information received from channel has label {}",
                backtrace.label()
            ),
            LabelBacktraceKind::FunctionParameter => format!(
                "function parameter `{}` has synthetic label {}",
                backtrace.symbol().unwrap_or("?"),
                backtrace.label()
            ),
            LabelBacktraceKind::FunctionArgument => format!(
                "{} in function call has label {}",
                symbol!("argument"),
                backtrace.label()
            ),
            LabelBacktraceKind::FunctionVariadicAggregation => format!(
                "argument aggregation for variadic parameter `{}` in function call has label {}",
                backtrace.symbol().unwrap_or("?"),
                backtrace.label()
            ),
            LabelBacktraceKind::Return => {
                format!("function returns with label {}", backtrace.label())
            }
            LabelBacktraceKind::BlackboxCall => format!(
                "blackbox call to function without known definition is assumed to yield value \
                 with label {}",
                backtrace.label()
            ),
            LabelBacktraceKind::SliceCopy => {
                format!(
                    "slice `copy` operation results in destination having label {}",
                    backtrace.label()
                )
            }
            LabelBacktraceKind::CollectionClear => {
                format!(
                    "collection `clear` operation results in operand having label {}",
                    backtrace.label()
                )
            }
            LabelBacktraceKind::ChannelClose => format!(
                "channel `close` operation results in operand having label {}",
                backtrace.label()
            ),
            LabelBacktraceKind::MapElementDelete => format!(
                "map element `delete` operation results in operand having label {}",
                backtrace.label()
            ),
            LabelBacktraceKind::EnforcementAggregation => format!(
                // in theory this will never be shown (will always be root)
                "the composition of all security factors results in label {}",
                backtrace.label()
            ),
        };

        (AnnotationKind::Context, label)
    };

    let mut snippets = vec![builder.snippet_for(backtrace.location().file()).annotate(
        StructuredAnnotation::new(kind, backtrace.location().inner().clone()).label(label),
    )];

    for child in backtrace.children() {
        snippets.extend(label_backtrace_to_snippets(child, None, builder));
    }

    snippets
}

// Given a vector of elements, if multiple snippets of the same file are
// presented in a row, all annotations are merged into one single snippet
fn collapse_snippets<'a>(snippets: Vec<StructuredSnippet<'a>>) -> Vec<StructuredSnippet<'a>> {
    let mut new = Vec::with_capacity(snippets.len());

    // we don't use `new.last_mut()` because `.extend` needs to take ownership
    // rather than just a mutable reference (since `.annotate` needs `self`);
    // instead, we use this `previous` variable and then commit it later
    let mut previous: Option<StructuredSnippet<'a>> = None;

    for snippet in snippets {
        if let Some(prev) = previous.take() {
            if snippet.path == prev.path {
                previous = Some(prev.extend(snippet.annotations));
            } else {
                new.push(prev); // commit

                previous = Some(snippet);
            }
        } else {
            previous = Some(snippet);
        }
    }

    new.extend(previous);

    new
}
