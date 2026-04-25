use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Instant,
};

use colored::Colorize;

use crate::{diagnostics, errors, fatal, presentation};

pub fn analyze_single<P: AsRef<Path>>(path: P, time_analysis: bool) -> (usize, usize) {
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
                if errors::error_category_to_level(category) == annotate_snippets::Level::ERROR {
                    error_count += 1;
                } else {
                    warning_count += 1;
                }

                let group = diagnostics::error_to_group(&error, &analyzer);
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

    // ilog10 cannot panic here since we already checked that len > 0 (is_empty)
    let width = 1 + modules.len().ilog10() as usize;
    let start = Instant::now();

    for (i, module) in modules.into_iter().enumerate() {
        let title = format!(
            "{} {} {}",
            format!("#{:0>width$} -", i + 1).cyan(),
            "Module @".blue(),
            module.to_string_lossy().purple()
        );
        println!("{}", presentation::build_header(title));

        results.push((
            module.to_string_lossy().into_owned(),
            analyze_single(module, time_analysis),
        ));

        println!("\n");
    }

    println!("{}", presentation::build_header("SUMMARY".cyan()));

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

pub fn analyze_suite<P: AsRef<Path>>(path: P, time_analysis: bool) -> (usize, usize) {
    let modules = list_dirs_in_dir(path).collect();

    analyze_multi(modules, time_analysis)
}

pub fn analyze_multi_suites<P: AsRef<Path>>(path: P, time_analysis: bool) -> (usize, usize) {
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
