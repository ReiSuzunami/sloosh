//! Daemon lifecycle and status commands.

use std::path::Path;

use super::args::{DaemonAction, StatusArgs};
use super::{client, display_host_list};
use crate::proto::{self, Request, Response, StatusReply};
use crate::transport::Channel;
use crate::transport::unix::{self, UnixChannel};

pub(super) async fn cmd_status(args: StatusArgs) -> anyhow::Result<()> {
    let socket_path = unix::resolve_socket_path();
    let mut channel = client::connect_or_spawn(&socket_path).await?;
    let reply = request_status(&mut channel).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&reply)?);
    } else {
        print_status_human(&reply, &socket_path);
    }
    Ok(())
}

pub(super) async fn cmd_daemon(action: DaemonAction) -> anyhow::Result<()> {
    let socket_path = unix::resolve_socket_path();
    match action {
        DaemonAction::Run => crate::daemon::run(socket_path).await,
        DaemonAction::Start => cmd_daemon_start(&socket_path).await,
        DaemonAction::Stop => cmd_daemon_stop(&socket_path).await,
        DaemonAction::Status => cmd_daemon_status(&socket_path).await,
    }
}

async fn cmd_daemon_start(socket_path: &Path) -> anyhow::Result<()> {
    match UnixChannel::connect(socket_path).await {
        Ok(_) => {
            println!(
                "sloosh daemon is already running (socket at {})",
                socket_path.display()
            );
            return Ok(());
        }
        Err(error) if daemon_is_not_running_error(&error) => {}
        Err(error) => return Err(daemon_connect_error(socket_path, error)),
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
    let mut channel = match UnixChannel::connect(socket_path).await {
        Ok(channel) => channel,
        Err(error) if daemon_is_not_running_error(&error) => {
            println!(
                "sloosh daemon is not running (no socket at {})",
                socket_path.display()
            );
            return Ok(());
        }
        Err(error) => return Err(daemon_connect_error(socket_path, error)),
    };
    channel.send(&Request::Shutdown).await?;
    // A closed connection also proves shutdown if the daemon exits before
    // flushing its acknowledgement.
    let _: Option<Response> = channel.recv().await.unwrap_or(None);
    println!("sloosh daemon stopped");
    Ok(())
}

async fn cmd_daemon_status(socket_path: &Path) -> anyhow::Result<()> {
    let mut channel = match UnixChannel::connect(socket_path).await {
        Ok(channel) => channel,
        Err(error) if daemon_is_not_running_error(&error) => {
            println!(
                "sloosh daemon is not running (no socket at {})",
                socket_path.display()
            );
            return Ok(());
        }
        Err(error) => return Err(daemon_connect_error(socket_path, error)),
    };
    let reply = request_status(&mut channel).await?;
    print_status_human(&reply, socket_path);
    Ok(())
}

pub(super) fn daemon_is_not_running_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
    )
}

pub(super) fn daemon_connect_error(socket_path: &Path, error: std::io::Error) -> anyhow::Error {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        client::untrusted_daemon_error(socket_path, error)
    } else {
        anyhow::Error::new(error).context(format!(
            "could not connect to the daemon socket at {}",
            socket_path.display()
        ))
    }
}

async fn request_status(channel: &mut UnixChannel) -> anyhow::Result<StatusReply> {
    channel.send(&Request::Status).await?;
    match channel.recv().await? {
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
    println!("  protocol: {}", reply.wire_protocol);
    println!("  uptime:   {}s", reply.uptime_secs);
    println!("  socket:   {}", socket_path.display());
    println!("  sessions: {}", reply.sessions.len());
    for session in &reply.sessions {
        println!(
            "    - {} @ {} [{}]",
            session.name, session.host, session.state
        );
    }
    println!("  leases:   {}", reply.leases.len());
    for lease in &reply.leases {
        println!(
            "    - {} — {} (pid {}), idle timeout in {}s",
            display_host_list(&lease.hosts),
            lease.anchor_name.as_deref().unwrap_or("unknown process"),
            lease.anchor_pid,
            lease.idle_remaining_secs,
        );
    }
}
