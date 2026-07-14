//! Daemon: accept loop and request routing (docs/internals/architecture.md).
//!
//! The daemon is a plain subcommand of the same binary (`sloosh daemon
//! run`), not a separate crate — see docs/internals/architecture.md "single binary". It owns
//! the Unix domain socket and answers the phase-1/phase-2 command surface:
//! `Status`/`Shutdown`, SSH session management (`Run`/`Peek`/`Send`/
//! `Interrupt`/`Open`/`Ls`/`Kill`), port forwarding (`Forward`/`ForwardLs`/
//! `ForwardStop`), and the vault/lease authorization flow
//! (`RequestLease`/`DescribeLeaseRequest`/`ApproveLease`/`VaultExists`/
//! `InitVault`/`AddCred`/`RmCred`).
//!
//! **Trust posture (docs/internals/architecture.md):** the Unix socket is still mode 0600
//! same-user-only (see `transport::unix`) — that's the outer perimeter. On
//! top of it, every host-touching request (`Run`/`Peek`/`Send`/`Interrupt`/
//! `Open`/`Kill`/`Forward`) additionally requires an active lease for that
//! host, checked via `lease::check_authorized` against the calling
//! process's ancestry (or its `SLOOSH_LEASE` escape-hatch token).
//! `Status`/`Ls`/`ForwardLs`/`ForwardStop`/`Daemon *` remain open to any
//! same-user caller: they're read-only, or (for `ForwardStop`) only ever
//! *reduce* access, matching the "these aren't host access" carve-out.
//! A forward's lease isn't just checked at creation, either — it dies the
//! moment its lease expires or is revoked, even though a shell session
//! survives that (`daemon::forward`'s module doc explains why).
//!
//! CLI-side TTY guards (`approve`/`add`/`rm`/`vault init`) only protect
//! those entry points: any same-user process can write raw NDJSON straight
//! to the socket, so every human-in-the-loop property must also hold
//! daemon-side. Concretely: `ApproveLease` never creates the vault (a
//! missing vault is a hard error pointing at `sloosh vault init`) and
//! rejects approvers whose ancestry contains the pending request's anchor
//! (self-approval). **Residual risk, accepted for this milestone:** a
//! *malicious* same-user process able to delete `~/.sloosh/vault` can race
//! a re-`InitVault` with its own password and then self-serve approvals —
//! same-user filesystem access is outside what a same-user daemon can
//! defend against on its own; true isolation needs OS help (keychain /
//! biometric-gated key storage), noted as future work.

pub mod audit;
pub mod forward;
pub mod lease;
pub mod session;
pub mod ssh;
pub mod vault;

use crate::proto::{self, Request, Response};
use crate::transport::unix;
use crate::transport::{BindOutcome, Channel, MAX_RAW_FRAME_BYTES};
use std::path::PathBuf;
use std::time::Instant;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

/// Self-teaching error for a host-touching request with no matching lease
/// (docs/internals/architecture.md).
fn no_lease_message(host: &str) -> String {
    format!(
        "no active lease for '{host}' — run `sloosh request {host}` and show your user the \
         approval command it prints (`sloosh approve <ID>`, run in another terminal); once \
         they approve it, retry this command."
    )
}

/// Gate a host-touching request behind an active lease. `peer` is the
/// caller's PID from `Channel::peer_pid` (looked up once per connection);
/// `lease_token` is the request's own `SLOOSH_LEASE` escape-hatch field, if
/// the caller's environment had one set.
async fn require_lease(
    peer: Option<u32>,
    host: &str,
    lease_token: &Option<String>,
) -> Result<(), Response> {
    let Some(pid) = peer else {
        return Err(Response::Error {
            message: format!(
                "could not determine the calling process's PID (peer credentials unavailable \
                 on this platform), so a lease for '{host}' can't be checked — this shouldn't \
                 happen on macOS/Linux; please file a bug"
            ),
        });
    };
    if lease::check_authorized(pid, host, lease_token.as_deref()).await {
        Ok(())
    } else {
        Err(Response::Error {
            message: no_lease_message(host),
        })
    }
}

/// Run the daemon accept loop until SIGTERM or a `Shutdown` request.
///
/// Binds `socket_path`; if another daemon already owns it (lost the
/// concurrent-auto-spawn race, docs/internals/architecture.md), exits quietly and lets the
/// winner serve — callers retry `connect`, they don't need this process to
/// succeed.
pub async fn run(socket_path: PathBuf) -> anyhow::Result<()> {
    let start = Instant::now();
    let pid = std::process::id();
    unix::ensure_private_dir(&unix::sloosh_home())?;

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
    // Cleared only after winning the bind: this daemon starts with no
    // sessions (a no-op in a real daemon process; see `reset_registry`).
    session::reset_registry().await;
    session::spawn_idle_reaper();
    lease::spawn_reaper();
    forward::reset_registry().await;
    forward::spawn_reaper();

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
    let mut negotiated = false;
    debug!(?peer, "connection accepted");

    loop {
        let req: Option<Request> = chan.recv().await?;
        let Some(req) = req else {
            debug!(?peer, "connection closed by peer");
            break;
        };
        debug!(request_type = req.kind(), ?peer, "request received");

        match req {
            Request::Status => {
                let reply = proto::StatusReply {
                    pid,
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    wire_protocol: proto::WIRE_PROTOCOL_VERSION,
                    uptime_secs: start.elapsed().as_secs(),
                    sessions: session::list_summaries().await,
                    leases: lease::list_summaries().await,
                };
                chan.send(&Response::Status(reply)).await?;
            }
            Request::Hello { wire_protocol } => {
                if wire_protocol == proto::WIRE_PROTOCOL_VERSION {
                    negotiated = true;
                    chan.send(&Response::ProtocolReady {
                        wire_protocol: proto::WIRE_PROTOCOL_VERSION,
                    })
                    .await?;
                } else {
                    negotiated = false;
                    chan.send(&Response::Error {
                        message: format!(
                            "incompatible wire protocol {wire_protocol}; this daemon requires {}. \
                             Run `sloosh daemon stop`, then retry with a matching CLI/daemon binary",
                            proto::WIRE_PROTOCOL_VERSION
                        ),
                    })
                    .await?;
                }
            }
            Request::Shutdown => {
                chan.send(&Response::Ok).await?;
                // Ignore send errors: if every receiver already dropped, the
                // accept loop is already gone.
                let _ = shutdown_tx.send(true);
                break;
            }
            ref request if !negotiated => {
                chan.send(&Response::Error {
                    message: format!(
                        "wire protocol handshake required before {}; use a matching sloosh CLI \
                         that sends Hello protocol {}",
                        request.kind(),
                        proto::WIRE_PROTOCOL_VERSION
                    ),
                })
                .await?;
            }
            Request::Run {
                host,
                command,
                session,
                timeout_secs,
                raw,
                lease_token,
            } => {
                let session_hint = session.clone().unwrap_or_else(|| "default".to_string());
                let resp = match require_lease(peer, &host, &lease_token).await {
                    Err(denied) => denied,
                    Ok(()) => {
                        let lease_ctx = ssh::LeaseContext {
                            caller_pid: peer.expect("require_lease Ok implies peer is Some"),
                            lease_token: lease_token.clone(),
                        };
                        audit::record(
                            "run_started",
                            serde_json::json!({
                                "host": host, "session": session_hint, "command": command,
                            }),
                        );
                        match session::run(&host, &command, session, timeout_secs, raw, lease_ctx)
                            .await
                        {
                            Ok(reply) => {
                                audit::record(
                                    "run_settled",
                                    serde_json::json!({
                                        "host": host, "session": reply.session,
                                        "command": command, "state": reply.state,
                                        "exit_code": reply.exit_code,
                                    }),
                                );
                                Response::Run(reply)
                            }
                            Err(e) => {
                                audit::record(
                                    "run_settled",
                                    serde_json::json!({
                                        "host": host, "session": session_hint, "command": command,
                                        "state": "error", "error": e.to_string(),
                                    }),
                                );
                                Response::Error {
                                    message: e.to_string(),
                                }
                            }
                        }
                    }
                };
                chan.send(&resp).await?;
            }
            Request::Peek {
                host,
                session,
                tail,
                raw,
                lease_token,
            } => {
                let resp = match require_lease(peer, &host, &lease_token).await {
                    Err(denied) => denied,
                    Ok(()) => match session::peek(&host, session, tail, raw).await {
                        Ok(reply) => Response::Peek(reply),
                        Err(e) => Response::Error {
                            message: e.to_string(),
                        },
                    },
                };
                chan.send(&resp).await?;
            }
            Request::Send {
                host,
                keys,
                session,
                newline,
                lease_token,
            } => {
                let session_hint = session.clone().unwrap_or_else(|| "default".to_string());
                let resp = match require_lease(peer, &host, &lease_token).await {
                    Err(denied) => denied,
                    Ok(()) => match session::send(&host, &keys, session, newline).await {
                        Ok(()) => {
                            // Never log `keys`: it can carry a password/answer
                            // typed into an interactive prompt (docs/internals/architecture.md).
                            audit::record(
                                "send",
                                serde_json::json!({"host": host, "session": session_hint}),
                            );
                            Response::Ok
                        }
                        Err(e) => Response::Error {
                            message: e.to_string(),
                        },
                    },
                };
                chan.send(&resp).await?;
            }
            Request::Interrupt {
                host,
                session,
                lease_token,
            } => {
                let session_hint = session.clone().unwrap_or_else(|| "default".to_string());
                let resp = match require_lease(peer, &host, &lease_token).await {
                    Err(denied) => denied,
                    Ok(()) => match session::interrupt(&host, session).await {
                        Ok(()) => {
                            audit::record(
                                "interrupt",
                                serde_json::json!({"host": host, "session": session_hint}),
                            );
                            Response::Ok
                        }
                        Err(e) => Response::Error {
                            message: e.to_string(),
                        },
                    },
                };
                chan.send(&resp).await?;
            }
            Request::Open {
                host,
                name,
                lease_token,
            } => {
                let resp = match require_lease(peer, &host, &lease_token).await {
                    Err(denied) => denied,
                    Ok(()) => {
                        let lease_ctx = ssh::LeaseContext {
                            caller_pid: peer.expect("require_lease Ok implies peer is Some"),
                            lease_token: lease_token.clone(),
                        };
                        match session::open(&host, &name, lease_ctx).await {
                            Ok(summary) => Response::Session(summary),
                            Err(e) => Response::Error {
                                message: e.to_string(),
                            },
                        }
                    }
                };
                chan.send(&resp).await?;
            }
            Request::Ls { host } => {
                let sessions = session::ls(host).await;
                chan.send(&Response::Ls { sessions }).await?;
            }
            Request::Kill {
                host,
                session,
                lease_token,
            } => {
                let session_hint = session.clone().unwrap_or_else(|| "default".to_string());
                let resp = match require_lease(peer, &host, &lease_token).await {
                    Err(denied) => denied,
                    Ok(()) => match session::kill(&host, session).await {
                        Ok(()) => {
                            audit::record(
                                "session_killed",
                                serde_json::json!({"host": host, "session": session_hint}),
                            );
                            Response::Ok
                        }
                        Err(e) => Response::Error {
                            message: e.to_string(),
                        },
                    },
                };
                chan.send(&resp).await?;
            }
            Request::Put {
                host,
                local_path,
                remote_path,
                session,
                lease_token,
            } => {
                if let Err(denied) = require_lease(peer, &host, &lease_token).await {
                    chan.send(&denied).await?;
                    continue;
                }
                let caller_pid = peer.expect("require_lease Ok implies peer is Some");
                let lease_ctx = ssh::LeaseContext {
                    caller_pid,
                    lease_token: lease_token.clone(),
                };
                let mut upload =
                    match session::begin_put(&host, session, &local_path, &remote_path, lease_ctx)
                        .await
                    {
                        Ok(upload) => upload,
                        Err(e) => {
                            chan.send(&Response::Error {
                                message: e.to_string(),
                            })
                            .await?;
                            continue;
                        }
                    };
                chan.send(&Response::TransferReady).await?;

                // A transfer is one finite operation authorized at start,
                // like `run`: lease expiry blocks new operations but does not
                // impose a time-derived size cap on an in-flight NAS copy.
                let mut stream_error = None;
                while let Some(chunk) = chan.recv_raw_frame().await? {
                    let chunk = Zeroizing::new(chunk);
                    if stream_error.is_some() {
                        continue;
                    }
                    if let Err(e) = upload.write_chunk(&chunk).await {
                        stream_error = Some(e.to_string());
                    }
                }
                let resp = match stream_error {
                    Some(message) => Response::Error { message },
                    None => match upload.finish().await {
                        Ok(reply) => Response::Transfer(reply),
                        Err(e) => Response::Error {
                            message: e.to_string(),
                        },
                    },
                };
                chan.send(&resp).await?;
            }
            Request::Get {
                host,
                remote_path,
                local_path,
                session,
                lease_token,
            } => {
                if let Err(denied) = require_lease(peer, &host, &lease_token).await {
                    chan.send(&denied).await?;
                    continue;
                }
                let caller_pid = peer.expect("require_lease Ok implies peer is Some");
                let lease_ctx = ssh::LeaseContext {
                    caller_pid,
                    lease_token: lease_token.clone(),
                };
                let mut download =
                    match session::begin_get(&host, session, &remote_path, &local_path, lease_ctx)
                        .await
                    {
                        Ok(download) => download,
                        Err(e) => {
                            chan.send(&Response::Error {
                                message: e.to_string(),
                            })
                            .await?;
                            continue;
                        }
                    };
                chan.send(&Response::TransferReady).await?;

                // Keep the start-time grant for the complete stream. New
                // transfers after expiry still fail at `require_lease` above.
                let mut buffer = Zeroizing::new(vec![0u8; MAX_RAW_FRAME_BYTES]);
                let stream_error = loop {
                    match download.read_chunk(buffer.as_mut_slice()).await {
                        Ok(0) => break None,
                        Ok(read) => chan.send_raw_frame(&buffer[..read]).await?,
                        Err(e) => break Some(e.to_string()),
                    }
                };
                chan.send_raw_frame(&[]).await?;
                let resp = match stream_error {
                    Some(message) => Response::Error { message },
                    None => Response::Transfer(download.finish()),
                };
                chan.send(&resp).await?;
            }
            Request::Forward {
                host,
                direction,
                lease_token,
            } => {
                let resp = match require_lease(peer, &host, &lease_token).await {
                    Err(denied) => denied,
                    Ok(()) => {
                        let lease_ctx = ssh::LeaseContext {
                            caller_pid: peer.expect("require_lease Ok implies peer is Some"),
                            lease_token: lease_token.clone(),
                        };
                        let opened = match direction {
                            proto::ForwardDirection::Local { spec } => {
                                forward::create_local(&host, &spec, lease_ctx).await
                            }
                            proto::ForwardDirection::Remote { spec } => {
                                forward::create_remote(&host, &spec, lease_ctx).await
                            }
                        };
                        match opened {
                            Ok(o) => Response::Forward(proto::ForwardOpened {
                                id: o.id,
                                host: o.host,
                                direction: o.direction,
                                spec: o.spec,
                                listen_addr: o.listen_addr,
                            }),
                            Err(e) => Response::Error {
                                message: e.to_string(),
                            },
                        }
                    }
                };
                chan.send(&resp).await?;
            }
            Request::ForwardLs => {
                let forwards = forward::ls().await;
                chan.send(&Response::ForwardLs { forwards }).await?;
            }
            Request::ForwardStop { id } => {
                let resp = match forward::stop(&id).await {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                };
                chan.send(&resp).await?;
            }
            Request::RequestLease { hosts } => {
                let Some(caller_pid) = peer else {
                    chan.send(&Response::Error {
                        message: "could not determine the calling process's PID (peer \
                                  credentials unavailable on this platform), so a lease \
                                  request can't be anchored"
                            .to_string(),
                    })
                    .await?;
                    continue;
                };
                // docs/internals/architecture.md: expand every requested host's ProxyJump
                // chain so the human approving this request sees (and
                // grants) coverage for the whole path, not just the target.
                let expanded_hosts = ssh::expand_lease_hosts(&hosts).await;
                let resp = match lease::request_lease(caller_pid, expanded_hosts.clone()).await {
                    Ok(outcome) => {
                        audit::record(
                            "lease_requested",
                            serde_json::json!({"hosts": expanded_hosts, "caller_pid": caller_pid}),
                        );
                        match outcome {
                            lease::RequestOutcome::AlreadyAuthorized => Response::Ok,
                            lease::RequestOutcome::Pending(info) => {
                                Response::LeaseRequestPending(info)
                            }
                        }
                    }
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                };
                chan.send(&resp).await?;
            }
            Request::DescribeLeaseRequest { id } => {
                let resp = match lease::describe_pending(&id).await {
                    Ok(info) => Response::LeaseRequestPending(info),
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                };
                chan.send(&resp).await?;
            }
            Request::ApproveLease {
                id,
                master_password,
                approved_hosts,
            } => {
                let Some(approver_pid) = peer else {
                    chan.send(&Response::Error {
                        message: "could not determine the approving process's PID (peer \
                                  credentials unavailable on this platform), so the \
                                  self-approval guard can't run; approval refused"
                            .to_string(),
                    })
                    .await?;
                    continue;
                };
                let resp = match lease::approve_lease(
                    approver_pid,
                    &id,
                    master_password.expose_secret().as_bytes(),
                    &approved_hosts,
                )
                .await
                {
                    Ok(mut info) => {
                        audit::record(
                            "lease_approved",
                            serde_json::json!({
                                "hosts": info.hosts, "anchor_name": info.anchor_name,
                                "anchor_pid": info.anchor_pid,
                            }),
                        );
                        // docs/internals/architecture.md: with the vault now unlocked, resolve
                        // each granted host the same way a real connection
                        // will (vault entry first) and tell the CLI which
                        // endpoints still need a host-key confirmation.
                        for host in &info.hosts {
                            let (hostname, port) = ssh::resolve_endpoint(host).await;
                            if !ssh::host_has_known_key(&hostname, port) {
                                info.unverified_hosts.push(proto::UnverifiedHostKey {
                                    host: host.clone(),
                                    hostname,
                                    port,
                                });
                            }
                        }
                        Response::LeaseActivated(info)
                    }
                    Err(e @ lease::LeaseError::SelfApproval { .. }) => {
                        audit::record(
                            "lease_denied_self_approval",
                            serde_json::json!({"request_id": id, "error": e.to_string()}),
                        );
                        Response::Error {
                            message: e.to_string(),
                        }
                    }
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                };
                chan.send(&resp).await?;
            }
            Request::VaultExists => {
                chan.send(&Response::VaultExists {
                    exists: vault::exists(),
                })
                .await?;
            }
            Request::InitVault { master_password } => {
                // `vault::create` refuses to overwrite an existing vault, so
                // this can't be used to reset someone else's master password.
                let resp = match vault::create(
                    &vault::VaultData::default(),
                    master_password.expose_secret().as_bytes(),
                ) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                };
                chan.send(&resp).await?;
            }
            Request::AddCred {
                alias,
                hostname,
                port,
                user,
                ssh_password,
                master_password,
                replace,
                jump,
            } => {
                let entry = vault::HostEntry {
                    hostname,
                    port,
                    user,
                    auth: vault::AuthMethod::Password {
                        password: ssh_password.into_string(),
                    },
                    jump,
                };
                let resp = match vault::add_entry(
                    &alias,
                    entry,
                    master_password.expose_secret().as_bytes(),
                    replace,
                )
                .await
                {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                };
                chan.send(&resp).await?;
            }
            Request::RmCred {
                alias,
                master_password,
            } => {
                let resp = match vault::rm_entry(&alias, master_password.expose_secret().as_bytes())
                    .await
                {
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
