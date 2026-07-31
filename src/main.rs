// Clippy lint configuration
#![warn(clippy::all, clippy::pedantic)]
// Forbid unsafe code
#![deny(unsafe_code)]

use std::{fmt, fs, path::PathBuf, process};

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
    let cli_config = CliConfig::parse();

    if let Some(Command::BaseSecurityPolicy { eject }) = cli_config.command {
        base_security_policy(eject);

        return;
    }

    diagnostics::N_CONTEXT_LINES
        .set(cli_config.context_lines)
        .unwrap(); // impossible for cell to already be initialized

    let config = orchestration::Config::from(cli_config);

    let (_warnings, errors) = orchestration::analyze(&config);

    if errors > 0 {
        process::exit(2)
    }
}

#[derive(clap::Parser)]
#[command(version, about, subcommand_negates_reqs = true)]
#[expect(clippy::struct_excessive_bools, reason = "Independent fields")]
struct CliConfig {
    /// Path to a directory containing a Go module, including a `go.mod` file.
    #[arg(required = true)] // positional
    directory: Option<PathBuf>,
    /// Upgrade all warnings to errors before reporting them.
    #[arg(long)]
    strict: bool,
    /// How many lines to show before and after error snippet annotations.
    #[arg(long, default_value = "1")]
    context_lines: usize,
    /// Analyze a directory of directories with Go modules, vs. just one module.
    #[arg(long, alias("multi"))]
    suite: bool,
    /// Analyze multiple suites (directories of directories with Go modules).
    #[arg(long)]
    multi_suites: bool,
    /// Omit per-module output when analyzing multiple modules.
    #[arg(long)]
    summary_only: bool,
    /// Report elapsed time for the entire analysis process (including parsing).
    #[arg(long)]
    time_analysis: bool,
    /// Additional auxiliary commands, in alternative to analysis.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Print the base security policy.
    BaseSecurityPolicy {
        /// Write the base security policy to `./glowy.toml` instead of stdout.
        ///
        /// If the file already exists, this will overwrite its contents
        /// entirely.
        #[arg(long)]
        eject: bool,
    },
}

fn base_security_policy(eject: bool) {
    if eject {
        fs::write("./glowy.toml", glowy::policy::BASE_SECURITY_POLICY).unwrap_or_else(|error| {
            fatal(
                "Failed to eject the base security policy to `./glowy.toml`.",
                "Do you have permission to write to the current directory?",
                Some(error),
            )
        });

        println!("Successfully ejected the base security policy to `./glowy.toml`!");
    } else {
        print!("{}", glowy::policy::BASE_SECURITY_POLICY);
    }
}

fn fatal(msg: &str, hint: &str, error: Option<impl fmt::Display>) -> ! {
    let error_section = if let Some(error) = error {
        format!("\n\n{}", error.to_string().trim())
    } else {
        String::new()
    };

    eprintln!(
        "{} {}{}\n\n\t{}",
        "[FATAL]".bold().bright_red(),
        msg.bright_red(),
        error_section,
        hint.italic().cyan()
    );
    process::exit(1)
}
