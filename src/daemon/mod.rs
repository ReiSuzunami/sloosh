//! Daemon: accept loop and request routing (DESIGN.md §1, §8).
//!
//! The daemon is a plain subcommand of the same binary (`sloosh daemon
//! run`), not a separate crate — see DESIGN.md §1 "single binary". It owns
//! the Unix domain socket and answers the phase-1/phase-2 command surface:
//! `Status`/`Shutdown` plus SSH session management (`Run`/`Peek`/`Send`/
//! `Interrupt`/`Open`/`Ls`/`Kill`).
//!
//! **Interim trust posture (milestone 2, DESIGN.md §4 not yet implemented):**
//! there is no vault and no lease enforcement yet. Authorization today is
//! entirely "same-user local trust": the Unix socket is mode 0600 and only
//! bound under `~/.sloosh` (see `transport::unix`), so the only access
//! control is that a connecting process must run as the same Unix user as
//! the daemon. Any such process can open SSH sessions to any host reachable
//! from `~/.ssh/config` and run arbitrary commands on it — there is no
//! per-host lease, no human-approval gate, and no audit log yet. Those land
//! with the vault/lease/audit modules in milestone 3.

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
    session::spawn_idle_reaper();

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
                    sessions: session::list_summaries().await,
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
            Request::Run {
                host,
                command,
                session,
                timeout_secs,
                raw,
            } => {
                let resp = match session::run(&host, &command, session, timeout_secs, raw).await {
                    Ok(reply) => Response::Run(reply),
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                };
                chan.send(&resp).await?;
            }
            Request::Peek {
                host,
                session,
                tail,
                raw,
            } => {
                let resp = match session::peek(&host, session, tail, raw).await {
                    Ok(reply) => Response::Peek(reply),
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                };
                chan.send(&resp).await?;
            }
            Request::Send {
                host,
                keys,
                session,
                newline,
            } => {
                let resp = match session::send(&host, &keys, session, newline).await {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                };
                chan.send(&resp).await?;
            }
            Request::Interrupt { host, session } => {
                let resp = match session::interrupt(&host, session).await {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                };
                chan.send(&resp).await?;
            }
            Request::Open { host, name } => {
                let resp = match session::open(&host, &name).await {
                    Ok(summary) => Response::Session(summary),
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                };
                chan.send(&resp).await?;
            }
            Request::Ls { host } => {
                let sessions = session::ls(host).await;
                chan.send(&Response::Ls { sessions }).await?;
            }
            Request::Kill { host, session } => {
                let resp = match session::kill(&host, session).await {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                };
                chan.send(&resp).await?;
            }
        }
    }

    Ok(())
}
