//! Dedicated sloosh daemon entry point.

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "slooshd",
    version,
    about = "Local daemon for sloosh SSH sessions and approvals"
)]
struct Args {
    /// DANGER: skip human lease approval and automatically trust unknown host keys.
    /// Known-key mismatches still fail; SSH authentication and vault encryption remain.
    /// Also enabled by dangerous_bypass_mode in local vault-settings.json; default off.
    #[arg(long)]
    dangerous_bypass_mode: bool,
}

#[tokio::main]
async fn main() {
    init_tracing();
    let args = Args::parse();

    if let Err(error) = sloosh::daemon::run_with_dangerous_bypass(
        sloosh::transport::unix::resolve_socket_path(),
        args.dangerous_bypass_mode,
    )
    .await
    {
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
