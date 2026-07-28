//! Entry point: parse the CLI and dispatch (docs/internals/architecture.md).

use clap::Parser;
use sloosh::cli::Cli;

#[tokio::main]
async fn main() {
    init_tracing();

    let cli = Cli::parse();
    if let Err(err) = sloosh::cli::dispatch(cli).await {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

/// Logs go to stderr by default (or wherever the daemon's stdio was
/// redirected to when auto-spawned/started — see `cli::client`).
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}
