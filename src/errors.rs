use glowy::{
    errors::{AnalysisErrorCategory, AnalysisErrorKind},
    labels::{Label, LabelBacktrace, LabelBacktraceKind},
};

use crate::diagnostics::{
    SnippetBuilder, StructuredAnnotation, StructuredErrorInfo, StructuredSnippet,
};

pub fn get_structured_error_info<'a>(
    kind: &'a AnalysisErrorKind<'a>,
    builder: &SnippetBuilder<'a>,
) -> StructuredErrorInfo<'a> {
    match kind {
        AnalysisErrorKind::Parsing(inner) => {
            let diagnostics = glowy::ParsingDiagnostics::diagnostics(inner);
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
        AnalysisErrorKind::TooManyBuildTagDimensions { limit, found } => StructuredErrorInfo {
            title: format!(
                "too many free build-tag dimensions: {} > limit {limit} (mentioned: [{}])",
                found.len(),
                found.iter().copied().collect::<Vec<_>>().join(", "),
            )
            .into(),
            code: "C002".into(),
            snippets: vec![],
            help: Some("consider raising the configured `max_build_tag_dimensions`"),
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

        AnalysisErrorKind::NoRegisteredFiles => StructuredErrorInfo {
            title: "no registered Go source code files".into(),
            code: "S001".into(),
            snippets: vec![],
            help: Some("did you forget to add files to be analyzed?"),
        },
        AnalysisErrorKind::InvalidDeclassificationSemantics { direct, location } => {
            StructuredErrorInfo {
                title: format!(
                    "illegal {} annotation with Bottom label",
                    if *direct {
                        "declassification"
                    } else {
                        "sanitizer"
                    }
                )
                .into(),
                code: "S002".into(),
                snippets: vec![builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone()).label(
                        "this is meaningless and likely indicates incorrect usage due to \
                         misconstrued semantics",
                    ),
                )],
                help: Some(
                    "Glowy interprets declassification as subtraction, not absolute overwriting",
                ),
            }
        }

        AnalysisErrorKind::InsecureFlow { sink, backtrace } => {
            let (context, operand) = match sink.kind {
                glowy::SinkKind::Declaration => ("declaration", "the initialization value"),
                glowy::SinkKind::Assignment => ("assignment expression", "provided right-value"),
                glowy::SinkKind::Call | glowy::SinkKind::Function => {
                    ("function call", "an argument")
                }
                glowy::SinkKind::Send => ("send statement", "the value being sent"),
            };

            StructuredErrorInfo {
                title: format!("insecure data flow to sink in {context}").into(),
                code: format!("F{:0>3}", sink.kind as usize + 1).into(),
                snippets: label_backtrace_to_snippets(
                    backtrace,
                    &sink.label,
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
                    expected,
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
        AnalysisErrorKind::InvalidReceiveOperand { location } => StructuredErrorInfo {
            title: "invalid operand in receive expression".into(),
            code: "G021".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("this expression cannot be resolved to a channel"),
                ),
            ],
            help: Some("check whether the specified operand is a channel"),
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
        AnalysisErrorKind::DeferNotCall { location } => StructuredErrorInfo {
            title: "illegal `defer` statement with a non-call expression".into(),
            code: "G023".into(),
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
            code: "G024".into(),
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
            code: "G025".into(),
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
            code: "G026".into(),
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
            code: "G027".into(),
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
            code: "G028".into(),
            snippets: vec![builder.snippet().annotate(
                StructuredAnnotation::primary(location.clone()).label(
                    "this expression yields multiple values, but only one value was expected",
                ),
            )],
            help: Some("ensure the expression's value-arity is compatible with where it is used"),
        },

        AnalysisErrorKind::DeferInInitNotDeferred { location } => StructuredErrorInfo {
            title: "unsupported `defer` statement in `init` function not deferred".into(),
            code: "U001".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("this expression was considered to execute immediately"),
                ),
            ],
            help: Some(
                "this analyzer version does not support `defer` statements in `init` functions",
            ),
        },
        AnalysisErrorKind::UnsoundFunctionMergingAssignment { location } => StructuredErrorInfo {
            title: "unsupported unsound assignment of non-portable function value".into(),
            code: "U002".into(),
            snippets: vec![
                builder.snippet().annotate(
                    StructuredAnnotation::primary(location.clone())
                        .label("these function values are not compatible"),
                ),
            ],
            help: Some(
                "this assignment is inside a control-flow split (e.g., an `if`), so the analyzer \
                 must merge the previous function value into the new one rather than overwrite \
                 it; discarding the previous value's body-derived analysis information would be \
                 unsound, so the construct is rejected with prejudice instead",
            ),
        },
    }
}

pub fn error_category_to_level(
    category: AnalysisErrorCategory,
) -> annotate_snippets::Level<'static> {
    // TODO: pedantic flag

    match category {
        AnalysisErrorCategory::Misconfiguration
        | AnalysisErrorCategory::SecurityPolicyViolation => annotate_snippets::Level::ERROR,
        AnalysisErrorCategory::UnrecognizedFeature
        | AnalysisErrorCategory::Suspicious
        | AnalysisErrorCategory::InvalidGo
        | AnalysisErrorCategory::UnsupportedGo => annotate_snippets::Level::WARNING,
    }
}

fn label_backtrace_to_snippets<'a>(
    backtrace: &'a LabelBacktrace<'a>,
    expected: &Label<'a>,
    root_label: Option<String>,
    builder: &SnippetBuilder<'a>,
) -> Vec<StructuredSnippet<'a>> {
    let (kind, label) = if let Some(label) = root_label {
        (annotate_snippets::AnnotationKind::Primary, label)
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
            LabelBacktraceKind::BlanketSource => format!(
                "{} is an explicitly registered blanket source with label {}",
                symbol!("function"),
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
            LabelBacktraceKind::MethodReceiver => {
                format!("method receiver has label {}", backtrace.label())
            }
            LabelBacktraceKind::ClosureCapture => format!(
                "outer symbol `{}` was captured by this closure and assigned synthetic label {}",
                backtrace.symbol().unwrap_or("?"),
                backtrace.label(),
            ),
            LabelBacktraceKind::ClosureCaptureBinding => format!(
                "captured symbol `{}` was bound at closure invocation with label {}",
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

        (annotate_snippets::AnnotationKind::Context, label)
    };

    let mut snippets = vec![builder.snippet_for(backtrace.location().file()).annotate(
        StructuredAnnotation::new(kind, backtrace.location().inner().clone()).label(label),
    )];

    let diff = if expected.is_subset_of(backtrace.label()) {
        // if the actual value just has more tags than the expected label, we
        // can reduce noise when displaying the error by focusing on just
        // highlighting why those tags are there (but shouldn't), ignoring those
        // that are present and are expected to be present
        Some(backtrace.label().difference(expected))
    } else {
        // never mind... use the whole thing
        None
    };

    for child in backtrace.children() {
        if diff
            .as_ref()
            .is_none_or(|diff| !child.label().intersect(diff).is_bottom())
        {
            snippets.extend(label_backtrace_to_snippets(child, expected, None, builder));
        }
    }

    snippets
}
