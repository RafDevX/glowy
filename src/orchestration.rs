use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Instant,
};

use colored::Colorize;

use crate::{CliConfig, diagnostics, errors, fatal, presentation};

pub struct Config {
    directory: PathBuf,
    mode: Mode,
    strict: bool,
    summary_only: bool,
    time_analysis: bool,
}

impl From<CliConfig> for Config {
    fn from(cli: CliConfig) -> Self {
        let mode = if cli.multi_suites {
            Mode::MultiSuites
        } else if cli.suite {
            Mode::Suite
        } else {
            Mode::Single
        };

        Self {
            directory: cli
                .directory
                .expect("clap requires a directory when no subcommand is provided"),
            mode,
            strict: cli.strict,
            summary_only: cli.summary_only,
            time_analysis: cli.time_analysis,
        }
    }
}

enum Mode {
    Single,
    Suite,
    MultiSuites,
}

pub fn analyze(config: &Config) -> (usize, usize) {
    match config.mode {
        Mode::Single => analyze_single(&config.directory, config, false),
        Mode::Suite => analyze_suite(config),
        Mode::MultiSuites => analyze_multi_suites(config),
    }
}

fn analyze_single<P: AsRef<Path>>(path: P, config: &Config, quiet: bool) -> (usize, usize) {
    let analyzer = glowy::Analyzer::from_directory(path).unwrap_or_else(|err| match err {
        glowy::AnalyzerFromDirectoryError::FileSystem(error) => fatal(
            "IO error occurred when reading the specified directory.",
            "Please try running Glowy again.",
            Some(error),
        ),
        glowy::AnalyzerFromDirectoryError::GoModFileNotFound => fatal(
            "No `go.mod` file found in the root of the specified directory",
            "Does a `go.mod` file exist?",
            None::<&str>,
        ),
        glowy::AnalyzerFromDirectoryError::UnknownModulePath => fatal(
            "Unknown module path.",
            "No `module` directive was found in the specified directory's `go.mod` file.",
            None::<&str>,
        ),
        glowy::AnalyzerFromDirectoryError::ConfigFileDeserializationFailure(error) => fatal(
            "Configuration file failed to deserialize.",
            "Is the `glowy.toml` file well-formed TOML structured how Glowy expects it to be?",
            Some(error),
        ),
        _ => fatal(
            "Unknown error occurred while bootstrapping the analyzer",
            "Please use an up-to-date version for more specific diagnostics",
            None::<&str>,
        ),
    });

    let start = Instant::now();

    let result = analyzer.analyze();

    if config.time_analysis && !quiet {
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
            if !quiet {
                println!("Analysis succeeded with no errors found!");
            }

            (0, 0)
        }
        Err(errors) => {
            let renderer = annotate_snippets::Renderer::styled();

            let mut warning_count = 0;
            let mut error_count = 0;

            for error in errors {
                let category = error.kind.category();
                let level = errors::error_category_to_level(category, config.strict);

                if level == annotate_snippets::Level::ERROR {
                    error_count += 1;
                } else {
                    warning_count += 1;
                }

                if !quiet {
                    let group = diagnostics::error_to_group(&error, &analyzer, config.strict);
                    let report = &[group];

                    anstream::eprintln!("{}", renderer.render(report));
                }
            }

            (warning_count, error_count)
        }
    }
}

fn analyze_multi(mut modules: Vec<PathBuf>, config: &Config) -> (usize, usize) {
    if modules.is_empty() {
        fatal(
            "No directories found in the specified modules directory.",
            "Is the provided path correct?",
            None::<&str>,
        )
    }

    modules.sort_unstable();

    let mut results = vec![];

    // ilog10 cannot panic here since we already checked that len > 0 (is_empty)
    let width = 1 + modules.len().ilog10() as usize;
    let start = Instant::now();

    for (i, module) in modules.into_iter().enumerate() {
        if !config.summary_only {
            let title = format!(
                "{} {} {}",
                format!("#{:0>width$} -", i + 1).cyan(),
                "Module @".blue(),
                module.to_string_lossy().purple()
            );
            println!("{}", presentation::build_header(title));
        }

        results.push((
            module.to_string_lossy().into_owned(),
            analyze_single(module, config, config.summary_only),
        ));

        if !config.summary_only {
            println!("\n");
        }
    }

    println!("{}", presentation::build_header("SUMMARY".cyan()));

    if config.time_analysis {
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

            // cannot use ⚠️ emoji as its width is calculated inconsistently
            // across different terminals - it should render as just one
            // character width, but since ⚠️ = U+26A0 (⚠) + U+FE0F (◌️), this
            // last code point (Variation Selector-16) that selects the
            // emoji-variant-style warning can sometimes cause the following
            // space to be ignored, meaning here that [ is placed one column too
            // early and breaks the summary lines' alignment -- e.g., it might
            // render as "- ⚠️[WARN] ..." instead of "- ⚠️ [WARN] ..."
            ("🟡", "WARN".yellow())
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
            format!(
                "({}, {})",
                presentation::format_count(*errors, "error", |s| s.bright_red()),
                presentation::format_count(*warnings, "warning", |s| s.yellow())
            )
            .italic()
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

fn analyze_suite(config: &Config) -> (usize, usize) {
    let modules = list_dirs_in_dir(&config.directory).collect();

    analyze_multi(modules, config)
}

fn analyze_multi_suites(config: &Config) -> (usize, usize) {
    let mut modules = vec![];

    for suite in list_dirs_in_dir(&config.directory) {
        let suite_modules = list_dirs_in_dir(suite);

        modules.extend(suite_modules);
    }

    analyze_multi(modules, config)
}

fn list_dirs_in_dir<P: AsRef<Path>>(path: P) -> impl Iterator<Item = PathBuf> {
    fs::read_dir(path)
        .and_then(Iterator::collect::<Result<Vec<_>, io::Error>>)
        .unwrap_or_else(|err| {
            fatal(
                "IO error occurred when reading the specified directory.",
                "Does the provided path exist?",
                Some(err),
            )
        })
        .into_iter()
        .filter(|entry| match entry.file_type() {
            Ok(file_type) => file_type.is_dir(),
            Err(err) => fatal(
                "IO error occurred while listing the specified directory.",
                "Do you have permission to access all of its contents?",
                Some(err),
            ),
        })
        .map(|entry| entry.path())
}
