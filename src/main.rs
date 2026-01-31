use std::{
    borrow::Cow,
    path::{Path, PathBuf},
    process,
};

use annotate_snippets::AnnotationKind;
use clap::Parser;
use glowy::{
    errors::{AnalysisError, AnalysisErrorCategory, AnalysisErrorKind},
    labels::{LabelBacktrace, LabelBacktraceKind},
};
use parser::Diagnostics;

// FIXME: change to proper hosted version
// (ideally, automatically updated with GitHub actions)
const DOCS_ROOT_URL: &str = "file:///home/raf/Documents/KTH/TCYSM/thesis/glowy/target/doc/glowy";

fn main() {
    let config = Config::parse();

    let analyzer = glowy::Analyzer::from_directory(&config.directory)
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

    let result = analyzer.analyze();

    match result {
        Ok(_) => println!("Analysis succeeded with no errors found!"),
        Err(errors) => {
            let renderer = annotate_snippets::Renderer::styled();

            let mut exit_failure = false;

            for error in errors {
                if !exit_failure
                    && error_category_to_level(error.kind.category())
                        == annotate_snippets::Level::ERROR
                {
                    exit_failure = true;
                }

                let group = error_to_group(&error, &analyzer);
                let report = &[group];

                anstream::eprintln!("{}", renderer.render(report));
            }

            if exit_failure {
                process::exit(2)
            }
        }
    }
}

#[derive(clap::Parser)]
#[command(version, about)]
struct Config {
    /// Path to a directory containing a Go module, including a `go.mod` file.
    directory: PathBuf,
    // ^ positional because no #[arg]
}

fn fatal(msg: &str, hint: &str) -> ! {
    eprintln!("[FATAL] {msg}\n\n\t{hint}");
    process::exit(1)
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

    fn snippet(&self) -> annotate_snippets::Snippet<'a, annotate_snippets::Annotation<'a>> {
        self.snippet_for(self.home)
    }

    fn snippet_for(
        &self,
        path: &'a Path,
    ) -> annotate_snippets::Snippet<'a, annotate_snippets::Annotation<'a>> {
        let source = self
            .analyzer
            .file_contents(path)
            .expect("specified error file not registered");

        annotate_snippets::Snippet::source(source).path(path.to_string_lossy())
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
struct StructuredErrorInfo<'a> {
    title: Cow<'a, str>,
    code: Cow<'a, str>,
    elements: Vec<annotate_snippets::Element<'a>>,
    help: Option<&'a str>,
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
        .elements(info.elements.into_iter().chain(help_msg))
}

fn get_structured_error_info<'a>(
    kind: &'a AnalysisErrorKind<'a>,
    builder: &SnippetBuilder<'a>,
) -> StructuredErrorInfo<'a> {
    match kind {
        AnalysisErrorKind::Parsing(inner) => {
            let diagnostics = inner.diagnostics();
            let location = if let Some(ctx) = diagnostics.context {
                ctx.location()
            } else {
                builder.eof()
            };

            StructuredErrorInfo {
                title: diagnostics.overview.into(),
                code: diagnostics.code.into(),
                elements: vec![
                    builder
                        .snippet()
                        .annotation(
                            AnnotationKind::Primary
                                .span(location)
                                .label(diagnostics.details),
                        )
                        .into(),
                ],
                help: None,
            }
        }

        AnalysisErrorKind::DuplicateVirtualFilePath => StructuredErrorInfo {
            title: format!("duplicate virtual file path `{}`", builder.home()).into(),
            code: "C001".into(),
            elements: vec![],
            help: Some(
                "another file with this virtual path had already been registered to the analyzer",
            ),
        },

        AnalysisErrorKind::UnknownAnnotationDirective {
            directive,
            location,
        } => StructuredErrorInfo {
            title: format!("unknown Glowy annotation directive `{directive}`").into(),
            code: "U001".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(AnnotationKind::Primary.span(location.clone()))
                    .into(),
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
                elements: label_backtrace_to_snippets(
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
        } => {
            StructuredErrorInfo {
                title: "expression label assertion is false".into(),
                code: "A001".into(),
                elements: if let Some(backtrace) = found {
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
                    vec![
                        builder
                            .snippet()
                            .annotation(AnnotationKind::Primary.span(location.clone()).label(
                                format!(
                                    "assertion expects label {}, but found Bottom (i.e., {})",
                                    expected,
                                    glowy::labels::Label::Bottom
                                ),
                            ))
                            .into(),
                    ]
                },
                help: Some(
                    "error reported because the expression label differed from the declared \
                     expectation",
                ),
            }
        }

        AnalysisErrorKind::DistinctPackageName { previous, found } => StructuredErrorInfo {
            title: format!(
                "declared package name `{}` differs from previously found `{}`",
                found.content(),
                previous.content()
            )
            .into(),
            code: "G001".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(found.location().clone())
                            .label(
                                "this package name does not match other files in the same \
                                 directory",
                            ),
                    )
                    .into(),
                builder
                    .snippet_for(previous.file())
                    .annotation(
                        AnnotationKind::Context
                            .span(previous.inner().location().clone())
                            .label("previously found this conflicting package name declaration"),
                    )
                    .into(),
            ],
            help: Some("due to the incompatibility, the file was excluded from the analysis"),
        },
        AnalysisErrorKind::UnresolvableUnqualifiedImport { location } => {
            StructuredErrorInfo {
                title: "could not resolve native qualifier for unknown package import".into(),
                code: "G002".into(),
                elements: vec![
                    builder
                        .snippet()
                        .annotation(AnnotationKind::Primary.span(location.clone()).label(
                            "cannot determine native package name, as it has not been analyzed",
                        ))
                        .into(),
                ],
                help: Some("consider manually specifying an import qualifier"),
            }
        }
        AnalysisErrorKind::DuplicateImportQualifier { location } => StructuredErrorInfo {
            title: "duplicate import qualifier within the same file".into(),
            code: "G003".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(location.clone())
                            .label("this illegally conflicts with a previous import declaration"),
                    )
                    .into(),
            ],
            help: Some("consider changing one of the qualifiers"),
        },
        AnalysisErrorKind::IllegalRedeclaration { previous, found } => StructuredErrorInfo {
            title: "illegal symbol redeclaration within same scope".into(),
            code: "G004".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(found.location().clone())
                            .label("this declaration conflicts with a previous one"),
                    )
                    .into(),
                builder
                    .snippet_for(previous.file())
                    .annotation(
                        AnnotationKind::Context
                            .span(previous.inner().location().clone())
                            .label("previously found this declaration"),
                    )
                    .into(),
            ],
            help: Some("check if your code meets Go's strict criteria for valid redeclarations"),
        },
        AnalysisErrorKind::UnknownSymbol { found } => StructuredErrorInfo {
            title: "invalid access of unknown symbol".into(),
            code: "G005".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(found.location().clone())
                            .label(
                                "this operand name could not be resolved within the current scope",
                            ),
                    )
                    .into(),
            ],
            help: Some("check if the operand name is spelled correctly"),
        },
        AnalysisErrorKind::UnknownQualifier { found } => StructuredErrorInfo {
            title: "invalid reference to unknown qualifier".into(),
            code: "G006".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(found.location().clone())
                            .label(
                                "this qualifier does not match any import declaration within the \
                                 current file",
                            ),
                    )
                    .into(),
            ],
            help: Some("check the file's import declarations"),
        },
        AnalysisErrorKind::UnexpectedReturn { location } => StructuredErrorInfo {
            title: "unexpected return statement outside a function definition".into(),
            code: "G007".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(location.clone())
                            .label("this return statement is illegal outside a function context"),
                    )
                    .into(),
            ],
            help: Some("fix the surrounding syntax to encapsulate the return in a function"),
        },
        AnalysisErrorKind::Unreachable { location } => StructuredErrorInfo {
            title: "unreachable statement found after a block-terminating statement".into(),
            code: "G008".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(AnnotationKind::Primary.span(location.clone()).label(
                        "this statement is unreachable since control flow is diverted before it",
                    ))
                    .into(),
            ],
            help: Some("consider moving the statement to run earlier in the block"),
        },
        AnalysisErrorKind::IllegalCallExpression { location } => {
            StructuredErrorInfo {
                title: "illegal call expression".into(),
                code: "G009".into(),
                elements: vec![
                    builder
                        .snippet()
                        .annotation(AnnotationKind::Primary.span(location.clone()).label(
                            "the expression being invoked could not be resolved to a function",
                        ))
                        .into(),
                ],
                help: Some("confirm that a function declaration was provided"),
            }
        }
        AnalysisErrorKind::IncorrectCallCardinality {
            expected,
            found,
            location,
        } => {
            StructuredErrorInfo {
                title: format!("expected {expected} arguments in function call, but found {found}")
                    .into(),
                code: "G010".into(),
                elements: vec![
                    builder
                        .snippet()
                        .annotation(AnnotationKind::Primary.span(location.clone()).label(
                            "incorrect call cardinality with regard to declared function arity",
                        ))
                        .into(),
                ],
                help: Some("check that the number of arguments is correct"),
            }
        }
        AnalysisErrorKind::UnexpectedBuiltInArgShape { location } => StructuredErrorInfo {
            title: "unexpected argument shape passed to built-in function".into(),
            code: "G011".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(location.clone())
                            .label("argument has a type not supported by this Go built-in"),
                    )
                    .into(),
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
            code: "G012".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(location.clone())
                            .label(format!(
                                "cannot assign {right} value(s) to {left} identifier(s)"
                            )),
                    )
                    .into(),
            ],
            help: Some("adjust one of the sides to match the other"),
        },
        AnalysisErrorKind::UnevenAssignment {
            location,
            left,
            right,
        } => StructuredErrorInfo {
            title: "mismatching number of left-values and expressions in binding declaration spec"
                .into(),
            code: "G013".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(location.clone())
                            .label(format!(
                                "cannot assign {right} right-value(s) to {left} left-value(s)"
                            )),
                    )
                    .into(),
            ],
            help: Some("adjust one of the sides to match the other"),
        },
        AnalysisErrorKind::MultiComplexAssignment { location, num } => StructuredErrorInfo {
            title: "invalid complex assignment with more than one left-value".into(),
            code: "G014".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(location.clone())
                            .label(format!(
                                "cannot perform a complex assignment on {num} left-values \
                                 simultaneously"
                            )),
                    )
                    .into(),
            ],
            help: Some("consider using a simple assignment (e.g., `=` instead of `+=`)"),
        },
        AnalysisErrorKind::InvalidLeftValue { location } => StructuredErrorInfo {
            title: "illegal or unsupported expression used as a left-value for assignment".into(),
            code: "G015".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(location.clone())
                            .label("this expression cannot be resolved to a valid left-value"),
                    )
                    .into(),
            ],
            help: Some("check whether the specified left-value is correct"),
        },
        AnalysisErrorKind::ImmutableLeftValue { symbol } => StructuredErrorInfo {
            title: "immutable left-value in assignment".into(),
            code: "G016".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(symbol.location().clone())
                            .label(format!(
                                "symbol `{}` is constant or unchangeable",
                                symbol.content()
                            )),
                    )
                    .into(),
            ],
            help: Some("check whether the specified left-value should be marked as immutable"),
        },
        AnalysisErrorKind::InvalidSelectionBase { location } => StructuredErrorInfo {
            title: "illegal or unsupported expression used as a selection base".into(),
            code: "G017".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(location.clone())
                            .label("this expression cannot be resolved to a valid selection base"),
                    )
                    .into(),
            ],
            help: Some("check whether the specified selection base is a struct"),
        },
        AnalysisErrorKind::InvalidIndexingBase { location } => StructuredErrorInfo {
            title: "illegal or unsupported expression used as an indexing base".into(),
            code: "G018".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(location.clone())
                            .label("this expression cannot be resolved to a valid indexing base"),
                    )
                    .into(),
            ],
            help: Some("check whether the specified selection base is an array/slice"),
        },
        AnalysisErrorKind::InvalidSlicingBase { location } => StructuredErrorInfo {
            title: "illegal or unsupported expression used as a slicing base".into(),
            code: "G019".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(location.clone())
                            .label("this expression cannot be resolved to a valid slicing base"),
                    )
                    .into(),
            ],
            help: Some("check whether the specified slicing base is a string/array/slice"),
        },
        AnalysisErrorKind::IllegalChannelExpression { location } => StructuredErrorInfo {
            title: "illegal or unsupported expression used as a channel in a send statement".into(),
            code: "G020".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(location.clone())
                            .label("this expression cannot be resolved to a channel"),
                    )
                    .into(),
            ],
            help: Some("check whether the specified expression is a channel"),
        },
        AnalysisErrorKind::GoNotCall { location } => StructuredErrorInfo {
            title: "illegal `go` statement with a non-call expression".into(),
            code: "G021".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(location.clone())
                            .label("this expression cannot be resolved to a function call"),
                    )
                    .into(),
            ],
            help: Some("check whether the specified expression is a function call"),
        },
        AnalysisErrorKind::UnexpectedFallthrough { location } => StructuredErrorInfo {
            title: "unexpected fallthrough statement".into(),
            code: "G022".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(location.clone())
                            .label("a fallthrough statement is illegal at this location"),
                    )
                    .into(),
            ],
            help: Some("ensure the statement is at the end of an expression switch clause"),
        },
        AnalysisErrorKind::DuplicateStructFieldName { duplicate } => StructuredErrorInfo {
            title: "duplicate field name in struct literal expression".into(),
            code: "G023".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(duplicate.location().clone())
                            .label("another field with this name has already been specified"),
                    )
                    .into(),
            ],
            help: Some("ensure there are no duplicate entries in the struct literal"),
        },
        AnalysisErrorKind::UnexpectedVoidExpression { location } => StructuredErrorInfo {
            title: "invalid void expression when a single value was expected".into(),
            code: "G024".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(
                        AnnotationKind::Primary
                            .span(location.clone())
                            .label("this expression yields no value, but one value was expected"),
                    )
                    .into(),
            ],
            help: Some("ensure the expression's value-arity is compatible with where it is used"),
        },
        AnalysisErrorKind::UnexpectedMultiValueExpression { location } => StructuredErrorInfo {
            title: "invalid multi-value expression when a single value was expected".into(),
            code: "G025".into(),
            elements: vec![
                builder
                    .snippet()
                    .annotation(AnnotationKind::Primary.span(location.clone()).label(
                        "this expression yields multiple values, but only one value was expected",
                    ))
                    .into(),
            ],
            help: Some("ensure the expression's value-arity is compatible with where it is used"),
        },
    }
}

#[inline]
fn error_category_to_level(category: AnalysisErrorCategory) -> annotate_snippets::Level<'static> {
    // TODO: pedantic flag

    match category {
        AnalysisErrorCategory::Misconfiguration
        | AnalysisErrorCategory::SecurityPolicyViolation => annotate_snippets::Level::ERROR,
        AnalysisErrorCategory::UnrecognizedFeature | AnalysisErrorCategory::InvalidGo => {
            annotate_snippets::Level::WARNING
        }
    }
}

fn label_backtrace_to_snippets<'a>(
    backtrace: &'a LabelBacktrace<'a>,
    root_label: Option<String>,
    builder: &SnippetBuilder<'a>,
) -> Vec<annotate_snippets::Element<'a>> {
    let (base, label) = if let Some(label) = root_label {
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
        };

        (AnnotationKind::Context, label)
    };

    let mut elements = vec![
        builder
            .snippet_for(backtrace.location().file())
            .annotation(base.span(backtrace.location().inner().clone()).label(label))
            .into(),
    ];

    for child in backtrace.children() {
        elements.extend(label_backtrace_to_snippets(child, None, builder));
    }

    elements
}
