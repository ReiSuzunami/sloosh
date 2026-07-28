//! Dedicated sloosh daemon entry point.

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "slooshd",
    version,
    about = "Local daemon for sloosh SSH sessions and approvals"
)]
struct Args {}

#[tokio::main]
async fn main() {
    init_tracing();
    Args::parse();

    if let Err(error) = sloosh::daemon::run(sloosh::transport::unix::resolve_socket_path()).await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}
