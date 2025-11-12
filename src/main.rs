use std::{path::PathBuf, process};

use clap::Parser;

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

    dbg!(&analyzer.analyze());

    todo!()
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
