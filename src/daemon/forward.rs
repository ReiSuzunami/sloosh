//! Port forwarding: `-L` (local) and `-R` (remote/reverse) tunnels through a
//! leased host (DESIGN.md §6).
//!
//! Each forward owns a dedicated [`ssh::Connection`], independent of any
//! shell session's (`daemon::session`) — a tunnel's lifecycle is simpler
//! (no PTY, no output framing) but its *fate on lease expiry* is different:
//! a shell session survives its creator's lease expiring (DESIGN.md §4), but
//! a forward is live network access sitting open on a socket, so it MUST be
//! torn down the moment the lease that justified it goes away.
//!
//! **Lease-expiry teardown** is driven by [`spawn_reaper`], a periodic sweep
//! that re-checks every live forward's lease via [`lease::peek_authorized`],
//! mirroring `session::spawn_idle_reaper`'s style rather than a push
//! notification *from* `lease.rs`: this module already depends on `lease.rs`
//! for the per-connection re-check (see `ssh::ForwardRoute` and the
//! accept-loop below), so a `lease.rs -> forward.rs` dependency the other
//! way would be a cycle. Polling reuses lease.rs's one authoritative expiry
//! decision instead of duplicating it, at the cost of teardown lagging real
//! expiry by up to [`REAP_SWEEP_INTERVAL`]. `-L` additionally re-checks on
//! every accepted connection (belt-and-suspenders — the reaper alone already
//! bounds the exposure window).
//!
//! **Idle refresh:** the sweep deliberately uses the non-touching
//! `peek_authorized` — a poll that refreshed `last_used` would keep every
//! forward-backed lease alive forever. Only real traffic winds the idle
//! clock: the accept-loop's per-connection `lease::check_authorized` (and
//! the equivalent check on incoming `-R` connections) touches the lease,
//! matching `run`'s idle-refresh behavior (DESIGN.md §4).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rand::RngCore;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex as AsyncMutex, oneshot, watch};
use tracing::{info, warn};

use crate::daemon::audit;
use crate::daemon::lease;
use crate::daemon::ssh::{self, ForwardRoute, LeaseContext, SshError};
use crate::proto::ForwardSummary;

/// How often [`spawn_reaper`] re-checks every live forward's lease
/// (DESIGN.md §4). Much tighter than `session`'s 5-minute idle sweep: a
/// forward is live network access, not an idle PTY, so the exposure window
/// after a lease expires/is revoked matters more than the sweep's overhead.
const REAP_SWEEP_INTERVAL: Duration = Duration::from_secs(15);
/// How often each forward's owner task polls its own SSH connection for
/// liveness, to notice a network drop (DESIGN.md §6 "SSH connection death")
/// even when no tunnel traffic is flowing to reveal it another way.
const HEALTH_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Crockford base32 (excludes I/L/O/U to avoid visual ambiguity), same
/// hand-rolled scheme as `lease::generate_request_id` — not shared as a
/// util because it's six lines and each module's id has a different prefix
/// and length.
const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const ID_RAW_LEN: usize = 8;

fn generate_forward_id() -> String {
    let mut raw = [0u8; ID_RAW_LEN];
    rand::rng().fill_bytes(&mut raw);
    let suffix: String = raw
        .iter()
        .map(|b| CROCKFORD_ALPHABET[(*b as usize) % CROCKFORD_ALPHABET.len()] as char)
        .collect();
    format!("fwd-{suffix}")
}

// ---------------------------------------------------------------------------
// Spec parsing
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error(
        "invalid -L forward spec '{spec}' — expected `[bind_addr:]local_port:remote_host:remote_port` \
         (e.g. `8080:127.0.0.1:80`, or `0.0.0.0:8080:127.0.0.1:80` to bind every local interface); \
         got {parts} colon-separated field(s), expected 3 or 4"
    )]
    BadLocalSpec { spec: String, parts: usize },

    #[error(
        "invalid -R forward spec '{spec}' — expected `[bind_addr:]remote_port:local_host:local_port` \
         (e.g. `8080:127.0.0.1:80` forwards the far host's port 8080 to this machine's 127.0.0.1:80); \
         got {parts} colon-separated field(s), expected 3 or 4"
    )]
    BadRemoteSpec { spec: String, parts: usize },

    #[error("'{value}' in forward spec '{spec}' is not a valid port number (0-65535)")]
    BadPort { spec: String, value: String },

    #[error("forward spec '{spec}' names an empty host — check for a stray `::`")]
    EmptyHost { spec: String },

    #[error(
        "forward spec '{spec}' targets port 0 — only the *listening* side of a forward may use 0 \
         for an OS-assigned port; the far end being dialed needs a real port number"
    )]
    ZeroTargetPort { spec: String },

    #[error(
        "bind address '{addr}' in forward spec '{spec}' is not a valid IP literal (e.g. 127.0.0.1 \
         or 0.0.0.0) — DNS names aren't supported for a `-L` forward's local listen side"
    )]
    BadBindAddr { spec: String, addr: String },

    #[error(
        "could not bind {addr} for the local forward — {source}. Something else may already be \
         listening on that port; pick a different local_port, or use 0 to let the OS choose one"
    )]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "{host} refused to open the remote forward on port {port} — {source}. Its sshd may have \
         `AllowTcpForwarding no` (or `no-port-forwarding` on the key), or something else on {host} \
         may already be bound to that port"
    )]
    RemoteForwardRefused {
        host: String,
        port: u16,
        #[source]
        source: russh::Error,
    },

    #[error(
        "unknown forward id '{id}' — `sloosh forward ls` lists the live ones; it may already have \
         been stopped, its lease may have expired, or the underlying SSH connection may have dropped"
    )]
    NotFound { id: String },

    #[error(transparent)]
    Ssh(#[from] SshError),
}

#[derive(Debug)]
pub struct LocalForwardSpec {
    pub bind_addr: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

#[derive(Debug)]
pub struct RemoteForwardSpec {
    pub bind_addr: String,
    pub remote_port: u16,
    pub local_host: String,
    pub local_port: u16,
}

/// Split a `[bind_addr:]port:host:port` spec into its 3-4 colon-separated
/// fields, OpenSSH `ssh(1)` `-L`/`-R` style. IPv6 literals and Unix-socket
/// forward forms (`ssh -L /path:host:port`) aren't supported in v1 — out of
/// scope, and a spec using them will simply fail to parse as too many/few
/// fields (or, for IPv6, as a bad port).
fn split_spec(spec: &str) -> Result<(Option<&str>, &str, &str, &str), usize> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.as_slice() {
        [port1, host, port2] => Ok((None, port1, host, port2)),
        [bind, port1, host, port2] => Ok((Some(bind), port1, host, port2)),
        other => Err(other.len()),
    }
}

fn parse_port(spec: &str, value: &str) -> Result<u16, ForwardError> {
    value.parse::<u16>().map_err(|_| ForwardError::BadPort {
        spec: spec.to_string(),
        value: value.to_string(),
    })
}

pub fn parse_local_spec(spec: &str) -> Result<LocalForwardSpec, ForwardError> {
    let (bind, port1, host, port2) =
        split_spec(spec).map_err(|parts| ForwardError::BadLocalSpec {
            spec: spec.to_string(),
            parts,
        })?;
    let local_port = parse_port(spec, port1)?;
    let remote_port = parse_port(spec, port2)?;
    if host.is_empty() {
        return Err(ForwardError::EmptyHost {
            spec: spec.to_string(),
        });
    }
    if remote_port == 0 {
        return Err(ForwardError::ZeroTargetPort {
            spec: spec.to_string(),
        });
    }
    Ok(LocalForwardSpec {
        bind_addr: bind
            .map(str::to_string)
            .unwrap_or_else(|| "127.0.0.1".to_string()),
        local_port,
        remote_host: host.to_string(),
        remote_port,
    })
}

pub fn parse_remote_spec(spec: &str) -> Result<RemoteForwardSpec, ForwardError> {
    let (bind, port1, host, port2) =
        split_spec(spec).map_err(|parts| ForwardError::BadRemoteSpec {
            spec: spec.to_string(),
            parts,
        })?;
    let remote_port = parse_port(spec, port1)?;
    let local_port = parse_port(spec, port2)?;
    if host.is_empty() {
        return Err(ForwardError::EmptyHost {
            spec: spec.to_string(),
        });
    }
    if local_port == 0 {
        return Err(ForwardError::ZeroTargetPort {
            spec: spec.to_string(),
        });
    }
    Ok(RemoteForwardSpec {
        bind_addr: bind
            .map(str::to_string)
            .unwrap_or_else(|| "127.0.0.1".to_string()),
        remote_port,
        local_host: host.to_string(),
        local_port,
    })
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Direction {
    Local,
    Remote,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::Local => "L",
            Direction::Remote => "R",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum StopReason {
    Requested,
    LeaseExpired,
    ConnectionLost,
}

impl StopReason {
    fn as_str(self) -> &'static str {
        match self {
            StopReason::Requested => "requested",
            StopReason::LeaseExpired => "lease_expired",
            StopReason::ConnectionLost => "connection_lost",
        }
    }
}

/// Registry entry: only what `ls` needs to display plus the handle to ask
/// the owner task to stop. No secrets — hosts/specs/ids only (DESIGN.md §7).
struct ForwardEntry {
    host: String,
    direction: Direction,
    spec: String,
    created_at: Instant,
    tunnel_count: Arc<AtomicUsize>,
    caller_pid: u32,
    lease_token: Option<String>,
    /// Sent exactly once, by whichever caller (`stop`, or the reaper) wins
    /// the race to `remove` this entry from the registry — removal doubles
    /// as the single-consumption guard, so no separate `Option`/lock is
    /// needed around the sender.
    stop_tx: oneshot::Sender<StopReason>,
}

fn registry() -> &'static AsyncMutex<HashMap<String, ForwardEntry>> {
    static REGISTRY: OnceLock<AsyncMutex<HashMap<String, ForwardEntry>>> = OnceLock::new();
    REGISTRY.get_or_init(|| AsyncMutex::new(HashMap::new()))
}

/// Drop every tracked forward's metadata (not the running tasks themselves —
/// this daemon process just started, so there are none). Mirrors
/// `session::reset_registry`'s role at daemon startup.
pub async fn reset_registry() {
    registry().lock().await.clear();
}

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

pub struct Opened {
    pub id: String,
    pub host: String,
    pub direction: String,
    pub spec: String,
    pub listen_addr: String,
}

pub async fn create_local(
    host: &str,
    spec_text: &str,
    lease_ctx: LeaseContext,
) -> Result<Opened, ForwardError> {
    let spec = parse_local_spec(spec_text)?;
    let ip: IpAddr = spec
        .bind_addr
        .parse()
        .map_err(|_| ForwardError::BadBindAddr {
            spec: spec_text.to_string(),
            addr: spec.bind_addr.clone(),
        })?;
    let addr = SocketAddr::new(ip, spec.local_port);
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| ForwardError::Bind { addr, source })?;
    let actual_port = listener
        .local_addr()
        .map(|a| a.port())
        .unwrap_or(spec.local_port);
    let listen_addr = format!("{}:{}", spec.bind_addr, actual_port);

    // Connect *after* the bind succeeds, so a busy local port fails fast
    // without ever touching the network (DESIGN.md §7: cheap failures first).
    let conn = ssh::connect(host, &lease_ctx).await?;

    let id = generate_forward_id();
    let tunnel_count = Arc::new(AtomicUsize::new(0));
    let (stop_tx, stop_rx) = oneshot::channel();
    let (closed_tx, closed_rx) = watch::channel(false);

    let entry = ForwardEntry {
        host: host.to_string(),
        direction: Direction::Local,
        spec: spec_text.to_string(),
        created_at: Instant::now(),
        tunnel_count: tunnel_count.clone(),
        caller_pid: lease_ctx.caller_pid,
        lease_token: lease_ctx.lease_token.clone(),
        stop_tx,
    };
    registry().lock().await.insert(id.clone(), entry);

    audit::record(
        "forward_opened",
        serde_json::json!({
            "id": id, "host": host, "direction": "L", "spec": spec_text,
        }),
    );

    tokio::spawn(run_local_forward(
        id.clone(),
        host.to_string(),
        listener,
        conn,
        spec.remote_host,
        spec.remote_port,
        lease_ctx.caller_pid,
        lease_ctx.lease_token,
        tunnel_count,
        closed_tx,
        closed_rx,
        stop_rx,
    ));

    Ok(Opened {
        id,
        host: host.to_string(),
        direction: "L".to_string(),
        spec: spec_text.to_string(),
        listen_addr,
    })
}

pub async fn create_remote(
    host: &str,
    spec_text: &str,
    lease_ctx: LeaseContext,
) -> Result<Opened, ForwardError> {
    let spec = parse_remote_spec(spec_text)?;
    let tunnel_count = Arc::new(AtomicUsize::new(0));
    let (closed_tx, closed_rx) = watch::channel(false);

    let route = ForwardRoute {
        local_host: spec.local_host.clone(),
        local_port: spec.local_port,
        caller_pid: lease_ctx.caller_pid,
        lease_host: host.to_string(),
        lease_token: lease_ctx.lease_token.clone(),
        tunnel_count: tunnel_count.clone(),
        closed: closed_rx.clone(),
    };
    let conn = ssh::connect_with_route(host, &lease_ctx, Some(route)).await?;

    let bound_port = conn
        .handle
        .tcpip_forward(spec.bind_addr.clone(), spec.remote_port as u32)
        .await
        .map_err(|source| ForwardError::RemoteForwardRefused {
            host: host.to_string(),
            port: spec.remote_port,
            source,
        })?;
    let actual_port = if spec.remote_port == 0 {
        bound_port as u16
    } else {
        spec.remote_port
    };
    let listen_addr = format!("{}:{}", spec.bind_addr, actual_port);

    let id = generate_forward_id();
    let (stop_tx, stop_rx) = oneshot::channel();
    let entry = ForwardEntry {
        host: host.to_string(),
        direction: Direction::Remote,
        spec: spec_text.to_string(),
        created_at: Instant::now(),
        tunnel_count: tunnel_count.clone(),
        caller_pid: lease_ctx.caller_pid,
        lease_token: lease_ctx.lease_token.clone(),
        stop_tx,
    };
    registry().lock().await.insert(id.clone(), entry);

    audit::record(
        "forward_opened",
        serde_json::json!({
            "id": id, "host": host, "direction": "R", "spec": spec_text,
        }),
    );

    tokio::spawn(run_remote_forward(
        id.clone(),
        host.to_string(),
        conn,
        spec.bind_addr,
        actual_port,
        closed_tx,
        stop_rx,
    ));

    Ok(Opened {
        id,
        host: host.to_string(),
        direction: "R".to_string(),
        spec: spec_text.to_string(),
        listen_addr,
    })
}

// ---------------------------------------------------------------------------
// Owner tasks
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run_local_forward(
    id: String,
    host: String,
    listener: TcpListener,
    conn: ssh::Connection,
    remote_host: String,
    remote_port: u16,
    caller_pid: u32,
    lease_token: Option<String>,
    tunnel_count: Arc<AtomicUsize>,
    closed_tx: watch::Sender<bool>,
    closed_rx: watch::Receiver<bool>,
    mut stop_rx: oneshot::Receiver<StopReason>,
) {
    let conn = Arc::new(conn);
    let mut health = tokio::time::interval(HEALTH_POLL_INTERVAL);
    health.tick().await; // consume the immediate first tick

    let reason = loop {
        tokio::select! {
            biased;
            stop_msg = &mut stop_rx => {
                break stop_msg.unwrap_or(StopReason::ConnectionLost);
            }
            _ = health.tick() => {
                if conn.handle.is_closed() {
                    registry().lock().await.remove(&id);
                    break StopReason::ConnectionLost;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _peer_addr)) => {
                        if !lease::check_authorized(caller_pid, &host, lease_token.as_deref()).await {
                            registry().lock().await.remove(&id);
                            break StopReason::LeaseExpired;
                        }
                        tokio::spawn(run_local_tunnel(
                            conn.clone(),
                            stream,
                            remote_host.clone(),
                            remote_port,
                            tunnel_count.clone(),
                            closed_rx.clone(),
                        ));
                    }
                    Err(e) => warn!(id = %id, error = %e, "local forward: accept failed"),
                }
            }
        }
    };

    let _ = closed_tx.send(true);
    drop(conn);
    audit::record(
        "forward_stopped",
        serde_json::json!({"id": id, "reason": reason.as_str()}),
    );
    info!(id = %id, host = %host, reason = reason.as_str(), "forward stopped");
}

async fn run_local_tunnel(
    conn: Arc<ssh::Connection>,
    mut local: TcpStream,
    remote_host: String,
    remote_port: u16,
    tunnel_count: Arc<AtomicUsize>,
    mut closed_rx: watch::Receiver<bool>,
) {
    match conn
        .handle
        .channel_open_direct_tcpip(remote_host.clone(), remote_port as u32, "127.0.0.1", 0)
        .await
    {
        Ok(channel) => {
            tunnel_count.fetch_add(1, Ordering::SeqCst);
            let mut remote = channel.into_stream();
            tokio::select! {
                _ = tokio::io::copy_bidirectional(&mut local, &mut remote) => {}
                _ = closed_rx.changed() => {}
            }
            tunnel_count.fetch_sub(1, Ordering::SeqCst);
        }
        Err(e) => {
            warn!(
                remote_host, remote_port, error = %e,
                "local forward: could not open direct-tcpip channel to target"
            );
        }
    }
}

async fn run_remote_forward(
    id: String,
    host: String,
    conn: ssh::Connection,
    bind_addr: String,
    remote_port: u16,
    closed_tx: watch::Sender<bool>,
    mut stop_rx: oneshot::Receiver<StopReason>,
) {
    let mut health = tokio::time::interval(HEALTH_POLL_INTERVAL);
    health.tick().await; // consume the immediate first tick

    let reason = loop {
        tokio::select! {
            biased;
            stop_msg = &mut stop_rx => {
                break stop_msg.unwrap_or(StopReason::ConnectionLost);
            }
            _ = health.tick() => {
                if conn.handle.is_closed() {
                    registry().lock().await.remove(&id);
                    break StopReason::ConnectionLost;
                }
            }
        }
    };

    let _ = closed_tx.send(true);
    // Best-effort: if the connection already died, cancelling the forward
    // request on it will simply fail too — nothing left to clean up remotely.
    let _ = conn
        .handle
        .cancel_tcpip_forward(bind_addr, remote_port as u32)
        .await;
    drop(conn);
    audit::record(
        "forward_stopped",
        serde_json::json!({"id": id, "reason": reason.as_str()}),
    );
    info!(id = %id, host = %host, reason = reason.as_str(), "forward stopped");
}

// ---------------------------------------------------------------------------
// Stop / list
// ---------------------------------------------------------------------------

/// Stop an active forward (DESIGN.md §6). No lease required: stopping only
/// ever reduces access.
pub async fn stop(id: &str) -> Result<(), ForwardError> {
    let entry = registry().lock().await.remove(id);
    match entry {
        Some(entry) => {
            // Ignore send failure: the owner task may have already exited
            // (e.g. it just self-detected connection loss and removed
            // itself) — nothing left to tell.
            let _ = entry.stop_tx.send(StopReason::Requested);
            Ok(())
        }
        None => Err(ForwardError::NotFound { id: id.to_string() }),
    }
}

/// List active forwards (DESIGN.md §6). No lease required: read-only.
pub async fn ls() -> Vec<ForwardSummary> {
    let reg = registry().lock().await;
    let mut out: Vec<ForwardSummary> = reg
        .iter()
        .map(|(id, e)| ForwardSummary {
            id: id.clone(),
            host: e.host.clone(),
            direction: e.direction.as_str().to_string(),
            spec: e.spec.clone(),
            tunnel_count: e.tunnel_count.load(Ordering::SeqCst),
            age_secs: e.created_at.elapsed().as_secs(),
        })
        .collect();
    drop(reg);
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

// ---------------------------------------------------------------------------
// Lease-expiry reaper
// ---------------------------------------------------------------------------

/// Spawn the background sweep that tears down any forward whose creator's
/// lease for its host has expired or been revoked (DESIGN.md §4, and the
/// module doc comment above for why this is a poll rather than a callback
/// from `lease.rs`).
pub fn spawn_reaper() {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(REAP_SWEEP_INTERVAL).await;
            reap_expired_leases().await;
        }
    });
}

async fn reap_expired_leases() {
    let candidates: Vec<(String, String, u32, Option<String>)> = {
        let reg = registry().lock().await;
        reg.iter()
            .map(|(id, e)| {
                (
                    id.clone(),
                    e.host.clone(),
                    e.caller_pid,
                    e.lease_token.clone(),
                )
            })
            .collect()
    };
    for (id, host, caller_pid, lease_token) in candidates {
        // peek, not check: this sweep must observe the idle clock, not wind
        // it — polling through the touching variant would keep every
        // forward-backed lease alive forever.
        if !lease::peek_authorized(caller_pid, &host, lease_token.as_deref()).await {
            let entry = registry().lock().await.remove(&id);
            if let Some(entry) = entry {
                let _ = entry.stop_tx.send(StopReason::LeaseExpired);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- spec parsing: -L --------------------------------------------------

    #[test]
    fn parses_local_spec_without_bind_addr() {
        let s = parse_local_spec("8080:example.com:80").unwrap();
        assert_eq!(s.bind_addr, "127.0.0.1");
        assert_eq!(s.local_port, 8080);
        assert_eq!(s.remote_host, "example.com");
        assert_eq!(s.remote_port, 80);
    }

    #[test]
    fn parses_local_spec_with_explicit_bind_addr() {
        let s = parse_local_spec("0.0.0.0:8080:127.0.0.1:80").unwrap();
        assert_eq!(s.bind_addr, "0.0.0.0");
        assert_eq!(s.local_port, 8080);
        assert_eq!(s.remote_host, "127.0.0.1");
        assert_eq!(s.remote_port, 80);
    }

    #[test]
    fn parses_local_spec_with_os_assigned_local_port() {
        let s = parse_local_spec("0:127.0.0.1:22").unwrap();
        assert_eq!(s.local_port, 0);
        assert_eq!(s.remote_port, 22);
    }

    #[test]
    fn rejects_local_spec_with_too_few_fields() {
        let e = parse_local_spec("8080:80").unwrap_err();
        assert!(matches!(e, ForwardError::BadLocalSpec { parts: 2, .. }));
    }

    #[test]
    fn rejects_local_spec_with_too_many_fields() {
        let e = parse_local_spec("a:b:8080:example.com:80").unwrap_err();
        assert!(matches!(e, ForwardError::BadLocalSpec { parts: 5, .. }));
    }

    #[test]
    fn rejects_local_spec_with_bad_port() {
        let e = parse_local_spec("notaport:example.com:80").unwrap_err();
        assert!(matches!(e, ForwardError::BadPort { .. }));
        let e = parse_local_spec("8080:example.com:notaport").unwrap_err();
        assert!(matches!(e, ForwardError::BadPort { .. }));
    }

    #[test]
    fn rejects_local_spec_with_empty_host() {
        let e = parse_local_spec("8080::80").unwrap_err();
        assert!(matches!(e, ForwardError::EmptyHost { .. }));
    }

    #[test]
    fn rejects_local_spec_with_zero_target_port() {
        let e = parse_local_spec("8080:example.com:0").unwrap_err();
        assert!(matches!(e, ForwardError::ZeroTargetPort { .. }));
    }

    // -- spec parsing: -R --------------------------------------------------

    #[test]
    fn parses_remote_spec_without_bind_addr() {
        let s = parse_remote_spec("9000:127.0.0.1:3000").unwrap();
        assert_eq!(s.bind_addr, "127.0.0.1");
        assert_eq!(s.remote_port, 9000);
        assert_eq!(s.local_host, "127.0.0.1");
        assert_eq!(s.local_port, 3000);
    }

    #[test]
    fn parses_remote_spec_with_explicit_bind_addr() {
        let s = parse_remote_spec("0.0.0.0:9000:127.0.0.1:3000").unwrap();
        assert_eq!(s.bind_addr, "0.0.0.0");
        assert_eq!(s.remote_port, 9000);
    }

    #[test]
    fn parses_remote_spec_with_os_assigned_remote_port() {
        let s = parse_remote_spec("0:127.0.0.1:3000").unwrap();
        assert_eq!(s.remote_port, 0);
        assert_eq!(s.local_port, 3000);
    }

    #[test]
    fn rejects_remote_spec_with_too_few_fields() {
        let e = parse_remote_spec("9000:3000").unwrap_err();
        assert!(matches!(e, ForwardError::BadRemoteSpec { parts: 2, .. }));
    }

    #[test]
    fn rejects_remote_spec_with_zero_target_port() {
        let e = parse_remote_spec("9000:127.0.0.1:0").unwrap_err();
        assert!(matches!(e, ForwardError::ZeroTargetPort { .. }));
    }

    #[test]
    fn rejects_remote_spec_with_empty_host() {
        let e = parse_remote_spec("9000::3000").unwrap_err();
        assert!(matches!(e, ForwardError::EmptyHost { .. }));
    }

    // -- id generation -------------------------------------------------

    #[test]
    fn forward_ids_have_expected_prefix_and_are_unique() {
        let a = generate_forward_id();
        let b = generate_forward_id();
        assert!(a.starts_with("fwd-"));
        assert!(b.starts_with("fwd-"));
        assert_ne!(a, b);
    }

    // -- registry stop/ls semantics -------------------------------------

    async fn insert_dummy_entry(id: &str, host: &str) -> oneshot::Receiver<StopReason> {
        let (stop_tx, stop_rx) = oneshot::channel();
        let entry = ForwardEntry {
            host: host.to_string(),
            direction: Direction::Local,
            spec: "8080:127.0.0.1:80".to_string(),
            created_at: Instant::now(),
            tunnel_count: Arc::new(AtomicUsize::new(0)),
            caller_pid: 1,
            lease_token: None,
            stop_tx,
        };
        registry().lock().await.insert(id.to_string(), entry);
        stop_rx
    }

    /// All registry tests share the one process-wide `registry()`; serialize
    /// them against each other (same pattern as `lease.rs`'s `test_lock`).
    fn test_lock() -> &'static AsyncMutex<()> {
        static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| AsyncMutex::new(()))
    }

    #[tokio::test]
    async fn stop_unknown_id_is_a_teaching_error() {
        let _guard = test_lock().lock().await;
        reset_registry().await;
        let e = stop("fwd-doesnotexist").await.unwrap_err();
        assert!(matches!(e, ForwardError::NotFound { .. }));
        assert!(e.to_string().contains("forward ls"));
    }

    #[tokio::test]
    async fn stop_known_id_signals_owner_and_removes_from_ls() {
        let _guard = test_lock().lock().await;
        reset_registry().await;
        let mut stop_rx = insert_dummy_entry("fwd-test1", "box").await;

        let before = ls().await;
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].id, "fwd-test1");
        assert_eq!(before[0].host, "box");
        assert_eq!(before[0].direction, "L");

        stop("fwd-test1").await.unwrap();

        let reason = stop_rx.try_recv().expect("owner task should be signalled");
        assert!(matches!(reason, StopReason::Requested));

        let after = ls().await;
        assert!(after.is_empty());
    }

    #[tokio::test]
    async fn stopping_twice_is_not_found_the_second_time() {
        let _guard = test_lock().lock().await;
        reset_registry().await;
        let _stop_rx = insert_dummy_entry("fwd-test2", "box").await;
        stop("fwd-test2").await.unwrap();
        let e = stop("fwd-test2").await.unwrap_err();
        assert!(matches!(e, ForwardError::NotFound { .. }));
    }

    #[tokio::test]
    async fn ls_reflects_multiple_forwards_sorted_by_id() {
        let _guard = test_lock().lock().await;
        reset_registry().await;
        let _a = insert_dummy_entry("fwd-bbbbbb", "host-b").await;
        let _b = insert_dummy_entry("fwd-aaaaaa", "host-a").await;
        let summaries = ls().await;
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].id, "fwd-aaaaaa");
        assert_eq!(summaries[1].id, "fwd-bbbbbb");
    }
}
