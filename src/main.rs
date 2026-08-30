//! Command-line entry point.

use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;

use headerscan::analyze::analyze;
use headerscan::fetch::{fetch, is_https, normalize_url};
use headerscan::report::{render_json, render_text};

/// Audit HTTP response security headers and grade them.
#[derive(Parser, Debug)]
#[command(name = "headerscan", version, about, long_about = None)]
struct Cli {
    /// URLs to scan. A missing scheme is assumed to be https.
    #[arg(required = true)]
    urls: Vec<String>,

    /// Output format.
    #[arg(short, long, default_value = "text", value_parser = ["text", "json"])]
    format: String,

    /// Request timeout in seconds.
    #[arg(short, long, default_value_t = 10)]
    timeout: u64,

    /// Do not follow redirects.
    #[arg(long)]
    no_redirects: bool,

    /// Disable ANSI colour.
    #[arg(long)]
    no_colour: bool,

    /// Exit non-zero when any target scores below this threshold.
    #[arg(long, default_value_t = 0)]
    min_score: u32,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let colour = !cli.no_colour && std::env::var_os("NO_COLOR").is_none();

    let mut reports = Vec::new();
    let mut failed = false;

    for url in &cli.urls {
        match fetch(url, Duration::from_secs(cli.timeout), !cli.no_redirects) {
            Ok(response) => {
                reports.push(analyze(
                    &response.url,
                    response.status,
                    &response.headers,
                    response.is_https,
                ));
            }
            Err(error) => {
                // One unreachable host must not abandon the remaining targets.
                eprintln!("{}: {error}", normalize_url(url));
                let _ = is_https(url);
                failed = true;
            }
        }
    }

    if cli.format == "json" {
        match render_json(&reports) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("could not serialise report: {error}");
                return ExitCode::from(2);
            }
        }
    } else {
        for report in &reports {
            print!("{}", render_text(report, colour));
        }
    }

    let below_threshold = reports.iter().any(|r| r.score < cli.min_score);
    if failed || below_threshold {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
