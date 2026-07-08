//! CLI: clap command definitions, client-side dispatch, daemon auto-spawn
//! (DESIGN.md §6, §8).

mod args;
mod client;

pub use args::Cli;
use args::{Command, DaemonAction, StatusArgs};

use crate::proto::{self, Request, Response, StatusReply};
use crate::transport::Channel;
use crate::transport::unix::{self, UnixChannel};
use std::path::Path;

/// Run the parsed CLI command. Errors are rendered by `main` and always
/// exit non-zero; nothing in here panics or uses `todo!()`.
pub async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Status(args) => cmd_status(args).await,
        Command::Daemon(args) => cmd_daemon(args.action).await,

        Command::Run(_) => not_implemented("run"),
        Command::Peek(_) => not_implemented("peek"),
        Command::Send(_) => not_implemented("send"),
        Command::Interrupt(_) => not_implemented("interrupt"),
        Command::Open(_) => not_implemented("open"),
        Command::Ls(_) => not_implemented("ls"),
        Command::Kill(_) => not_implemented("kill"),
        Command::Request(_) => not_implemented("request"),
        Command::Approve(_) => not_implemented("approve"),
        Command::Add(_) => not_implemented("add"),
        Command::Rm(_) => not_implemented("rm"),
        Command::Put(_) => not_implemented("put"),
        Command::Get(_) => not_implemented("get"),
        Command::Log(_) => not_implemented("log"),
    }
}

fn not_implemented(name: &str) -> anyhow::Result<()> {
    anyhow::bail!(
        "`sloosh {name}` is not implemented yet. Milestone 1 only wires up `status` and `daemon`; \
         see DESIGN.md §6 for the full phase-1 command surface as it lands."
    )
}

async fn cmd_status(args: StatusArgs) -> anyhow::Result<()> {
    let socket_path = unix::resolve_socket_path();
    let mut chan = client::connect_or_spawn(&socket_path).await?;
    let reply = request_status(&mut chan).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&reply)?);
    } else {
        print_status_human(&reply, &socket_path);
    }
    Ok(())
}

async fn cmd_daemon(action: DaemonAction) -> anyhow::Result<()> {
    let socket_path = unix::resolve_socket_path();
    match action {
        DaemonAction::Run => crate::daemon::run(socket_path).await,
        DaemonAction::Start => cmd_daemon_start(&socket_path).await,
        DaemonAction::Stop => cmd_daemon_stop(&socket_path).await,
        DaemonAction::Status => cmd_daemon_status(&socket_path).await,
    }
}

async fn cmd_daemon_start(socket_path: &Path) -> anyhow::Result<()> {
    if UnixChannel::connect(socket_path).await.is_ok() {
        println!(
            "sloosh daemon is already running (socket at {})",
            socket_path.display()
        );
        return Ok(());
    }
    client::spawn_daemon_detached(socket_path)?;
    client::wait_for_daemon(socket_path).await?;
    println!(
        "sloosh daemon started (socket at {})",
        socket_path.display()
    );
    Ok(())
}

async fn cmd_daemon_stop(socket_path: &Path) -> anyhow::Result<()> {
    let Ok(mut chan) = UnixChannel::connect(socket_path).await else {
        println!(
            "sloosh daemon is not running (no socket at {})",
            socket_path.display()
        );
        return Ok(());
    };
    chan.send(&Request::Shutdown).await?;
    // Best-effort: read the Ok ack, but a closed connection is also a valid
    // sign the daemon shut down before flushing its reply.
    let _: Option<Response> = chan.recv().await.unwrap_or(None);
    println!("sloosh daemon stopped");
    Ok(())
}

async fn cmd_daemon_status(socket_path: &Path) -> anyhow::Result<()> {
    let Ok(mut chan) = UnixChannel::connect(socket_path).await else {
        println!(
            "sloosh daemon is not running (no socket at {})",
            socket_path.display()
        );
        return Ok(());
    };
    let reply = request_status(&mut chan).await?;
    print_status_human(&reply, socket_path);
    Ok(())
}

async fn request_status(chan: &mut UnixChannel) -> anyhow::Result<StatusReply> {
    chan.send(&Request::Status).await?;
    match chan.recv().await? {
        Some(Response::Status(reply)) => Ok(reply),
        Some(Response::Error { message }) => anyhow::bail!("daemon reported an error: {message}"),
        Some(other) => anyhow::bail!("daemon sent an unexpected reply: {other:?}"),
        None => anyhow::bail!(
            "daemon closed the connection without responding to Status; \
             check ~/.sloosh/daemon.log for a crash"
        ),
    }
}

fn print_status_human(reply: &proto::StatusReply, socket_path: &Path) {
    println!("sloosh daemon: running (pid {})", reply.pid);
    println!("  version:  {}", reply.version);
    println!("  uptime:   {}s", reply.uptime_secs);
    println!("  socket:   {}", socket_path.display());
    println!("  sessions: {}", reply.sessions.len());
    for s in &reply.sessions {
        println!("    - {} @ {} [{}]", s.name, s.host, s.state);
    }
    println!("  leases:   {}", reply.leases.len());
    for l in &reply.leases {
        println!("    - {} (expires in {}s)", l.host, l.expires_in_secs);
    }
}
