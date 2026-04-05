use std::{path::PathBuf, process};

use clap::Parser;
use colored::Colorize;

mod diagnostics;
mod errors;
mod orchestration;
mod presentation;

#[cfg(not(debug_assertions))] // release mode
const DOCS_ROOT_URL: &str = "https://glowy.rso.pt/glowy";
#[cfg(debug_assertions)] // debug mode
const DOCS_ROOT_URL: &str = concat!("file://", env!("CARGO_MANIFEST_DIR"), "/target/doc/glowy",);

fn main() {
    let config = Config::parse();

    let (_warnings, errors) = if config.multi_suites {
        orchestration::analyze_multi_suites(&config.directory, config.time_analysis)
    } else if config.suite {
        orchestration::analyze_suite(&config.directory, config.time_analysis)
    } else {
        orchestration::analyze_single(&config.directory, config.time_analysis)
    };

    if errors > 0 {
        process::exit(2)
    }
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

fn fatal(msg: &str, hint: &str) -> ! {
    eprintln!(
        "{} {}\n\n\t{}",
        "[FATAL]".bold().bright_red(),
        msg.bright_red(),
        hint.italic().cyan()
    );
    process::exit(1)
}
