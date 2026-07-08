//! Daemon: accept loop and request routing (DESIGN.md §1, §8).
//!
//! The daemon is a plain subcommand of the same binary (`sloosh daemon
//! run`), not a separate crate — see DESIGN.md §1 "single binary". It owns
//! the Unix domain socket, answers `Status`/`Shutdown` today, and will grow
//! session/ssh/lease/vault/audit wiring in later milestones.

pub mod audit;
pub mod lease;
pub mod session;
pub mod ssh;
pub mod vault;

use crate::proto::{self, Request, Response};
use crate::transport::BindOutcome;
use crate::transport::Channel;
use crate::transport::unix;
use std::path::PathBuf;
use std::time::Instant;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Run the daemon accept loop until SIGTERM or a `Shutdown` request.
///
/// Binds `socket_path`; if another daemon already owns it (lost the
/// concurrent-auto-spawn race, DESIGN.md §1), exits quietly and lets the
/// winner serve — callers retry `connect`, they don't need this process to
/// succeed.
pub async fn run(socket_path: PathBuf) -> anyhow::Result<()> {
    let start = Instant::now();
    let pid = std::process::id();

    let listener = match unix::bind(&socket_path)? {
        BindOutcome::Bound(listener) => listener,
        BindOutcome::AlreadyRunning => {
            info!(
                path = %socket_path.display(),
                "another sloosh daemon already owns this socket, exiting"
            );
            return Ok(());
        }
    };

    info!(pid, path = %socket_path.display(), version = env!("CARGO_PKG_VERSION"), "sloosh daemon listening");

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let mut sigterm = signal(SignalKind::terminate())?;

    loop {
        tokio::select! {
            biased;
            _ = sigterm.recv() => {
                info!("received SIGTERM, shutting down");
                break;
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("shutdown requested, shutting down");
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok(chan) => {
                        let tx = shutdown_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(chan, start, pid, tx).await {
                                warn!(error = %e, "connection handler error");
                            }
                        });
                    }
                    Err(e) => warn!(error = %e, "accept failed"),
                }
            }
        }
    }

    Ok(())
}

async fn handle_connection(
    mut chan: unix::UnixChannel,
    start: Instant,
    pid: u32,
    shutdown_tx: watch::Sender<bool>,
) -> anyhow::Result<()> {
    let peer = chan.peer_pid().unwrap_or(None);
    debug!(?peer, "connection accepted");

    loop {
        let req: Option<Request> = chan.recv().await?;
        let Some(req) = req else {
            debug!(?peer, "connection closed by peer");
            break;
        };
        debug!(?req, ?peer, "request received");

        match req {
            Request::Status => {
                let reply = proto::StatusReply {
                    pid,
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    uptime_secs: start.elapsed().as_secs(),
                    sessions: session::list_summaries(),
                    leases: lease::list_summaries(),
                };
                chan.send(&Response::Status(reply)).await?;
            }
            Request::Shutdown => {
                chan.send(&Response::Ok).await?;
                // Ignore send errors: if every receiver already dropped, the
                // accept loop is already gone.
                let _ = shutdown_tx.send(true);
                break;
            }
        }
    }

    Ok(())
}
