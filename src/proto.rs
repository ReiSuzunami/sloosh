//! NDJSON wire protocol between the `sloosh` CLI and `sloosh daemon`.
//!
//! Control messages are single JSON objects serialized one per line (NDJSON),
//! so ordinary request/reply traffic stays inspectable without a schema
//! compiler. SFTP payload bytes switch the same connection to bounded raw
//! frames after `TransferReady`; see `docs/PROTOCOL.md`. Enums are internally
//! tagged (`"type"` field). Unknown fields are ignored by serde by default,
//! and `#[serde(default)]` lets old messages satisfy selected newly-added
//! fields. New variants or sequencing changes are not inherently compatible,
//! so clients verify [`WIRE_PROTOCOL_VERSION`] through `Status` before
//! sending ordinary requests.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

/// Control messages are small JSON objects. File bytes use the transport's
/// separate bounded-frame stream, so a large file never needs a large JSON
/// allocation.
pub const MAX_WIRE_MESSAGE_BYTES: usize = 1024 * 1024;

/// Exact CLI/daemon wire contract version. Bump this for any incompatible
/// message shape or sequencing change; package versions may differ while this
/// remains equal.
pub const WIRE_PROTOCOL_VERSION: u32 = 2;

/// A password/secret that crosses the CLI<->daemon socket (DESIGN.md §4:
/// "passwords/keys crossing the socket is acceptable, same-user 0600" — but
/// they must never leak into logs). Wraps a `String` with a `Debug` impl
/// that always prints a fixed redacted placeholder, so deriving `Debug` on
/// any `Request`/`Response` variant that embeds one (as `daemon/mod.rs`'s
/// `debug!(?req, ...)` does for every inbound message) can never print the
/// secret. Zeroized on drop.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow the secret, e.g. to pass to `vault::unlock`/`add_entry`.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Take ownership of the secret as a plain `String` (e.g. to store it as
    /// a vault `HostEntry`'s password field, where the vault's own zeroize
    /// coverage takes over). Leaves this `SecretString` holding an empty
    /// string, which is still zeroized (as a no-op) on drop.
    pub fn into_string(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString(<redacted>)")
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A request sent from the CLI to the daemon.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Request {
    /// Report daemon health: pid, version, uptime, live sessions and leases.
    Status,
    /// Negotiate the exact wire contract before any ordinary request. Status
    /// and Shutdown remain available without this handshake so a newer CLI
    /// can inspect and stop an older resident daemon.
    Hello { wire_protocol: u32 },
    /// Ask the daemon to shut down gracefully after replying `Ok`.
    Shutdown,
    /// Run a command in a host's default (or named) session, auto-creating
    /// it if needed (DESIGN.md §3 "隐式寻址"). Blocks until the sentinel is
    /// seen or `timeout_secs` elapses.
    Run {
        host: String,
        command: String,
        #[serde(default)]
        session: Option<String>,
        #[serde(default = "default_run_timeout_secs")]
        timeout_secs: u64,
        #[serde(default)]
        raw: bool,
        /// `SLOOSH_LEASE` escape-hatch token, if the caller's environment
        /// had one set (DESIGN.md §4). Checked before ancestry matching.
        #[serde(default)]
        lease_token: Option<String>,
    },
    /// Fetch output a session has produced since the last `Peek` (or the
    /// last `tail` bytes, if given — which does not advance the cursor).
    Peek {
        host: String,
        #[serde(default)]
        session: Option<String>,
        #[serde(default)]
        tail: Option<usize>,
        #[serde(default)]
        raw: bool,
        #[serde(default)]
        lease_token: Option<String>,
    },
    /// Write raw bytes/keystrokes to a session's PTY.
    Send {
        host: String,
        keys: String,
        #[serde(default)]
        session: Option<String>,
        #[serde(default)]
        newline: bool,
        #[serde(default)]
        lease_token: Option<String>,
    },
    /// Send Ctrl-C (0x03) to a session's PTY.
    Interrupt {
        host: String,
        #[serde(default)]
        session: Option<String>,
        #[serde(default)]
        lease_token: Option<String>,
    },
    /// Explicitly open (create-or-reuse) a named parallel session on a host.
    Open {
        host: String,
        name: String,
        #[serde(default)]
        lease_token: Option<String>,
    },
    /// List known sessions, optionally filtered by host. Not gated by a
    /// lease (DESIGN.md §4: `status`/`ls`/`daemon *` remain open).
    Ls {
        #[serde(default)]
        host: Option<String>,
    },
    /// Kill a session, terminating the remote shell.
    Kill {
        host: String,
        #[serde(default)]
        session: Option<String>,
        #[serde(default)]
        lease_token: Option<String>,
    },
    /// Request an access lease for one or more hosts (agent side of
    /// DESIGN.md §4's out-of-band approval flow).
    RequestLease { hosts: Vec<String> },
    /// Fetch details of a still-pending lease request, for the human about
    /// to `approve` it.
    DescribeLeaseRequest { id: String },
    /// Approve a pending lease request (human side, TTY-only on the CLI).
    ApproveLease {
        id: String,
        master_password: SecretString,
        /// Exact host list the human saw and confirmed after locally
        /// unlocking the vault and expanding every ProxyJump chain. The
        /// daemon independently repeats that expansion after unlocking its
        /// own vault cache and refuses activation unless the lists match.
        ///
        /// Defaulting keeps an older client's message parseable, but the
        /// empty list cannot match a real non-empty request, so it fails
        /// closed with a self-teaching approval error.
        #[serde(default)]
        approved_hosts: Vec<String>,
    },
    /// Whether a vault exists yet, so `add`/`approve` can decide whether to
    /// walk the human through first-time master-password setup.
    VaultExists,
    /// Create an empty vault with a freshly-set master password (`sloosh
    /// vault init`, human-only, TTY-required on the CLI side). Fails if a
    /// vault already exists. This is deliberately the ONLY path (besides
    /// `AddCred`'s create-on-first-use, which shares its trust posture) that
    /// can create the vault: `ApproveLease` never does, so a request can't
    /// be self-approved by inventing a master password on a fresh install.
    InitVault { master_password: SecretString },
    /// Add (or replace) a credential in the vault, creating the vault on
    /// first use. Human-only, TTY-required on the CLI side (DESIGN.md §4 §2)
    /// — the daemon does the KDF + file I/O so it stays the single writer
    /// and can refresh its cache.
    AddCred {
        alias: String,
        hostname: String,
        #[serde(default)]
        port: Option<u16>,
        #[serde(default)]
        user: Option<String>,
        ssh_password: SecretString,
        master_password: SecretString,
        #[serde(default)]
        replace: bool,
        /// Optional jump host alias (DESIGN.md §4), resolvable via the
        /// vault or `~/.ssh/config`. `#[serde(default)]` so older CLI/daemon
        /// builds exchanging this message without the field keep working.
        #[serde(default)]
        jump: Option<String>,
    },
    /// Remove a credential from the vault.
    RmCred {
        alias: String,
        master_password: SecretString,
    },
    /// Upload a local file to a host over SFTP, reusing the target
    /// session's existing SSH connection (DESIGN.md §5: "put/get 走既有连接
    /// 的 SFTP channel" — no redial/reauth per transfer). The CLI resolves
    /// `local_path` to an absolute path before sending: the daemon's
    /// working directory is not the caller's, so a relative path here would
    /// resolve against the wrong place. Overwriting an existing file at
    /// `remote_path` is allowed unconditionally — the remote host is the
    /// disposable workspace.
    Put {
        host: String,
        /// Label for audit/output only. The daemon never opens this path;
        /// bytes follow as bounded raw frames after `TransferReady`.
        local_path: String,
        remote_path: String,
        #[serde(default)]
        session: Option<String>,
        #[serde(default)]
        lease_token: Option<String>,
    },
    /// Download a remote file to the local filesystem over SFTP, same
    /// connection-reuse contract as `Put`. The daemon treats `local_path` as
    /// a label only; overwrite policy and atomic commit are enforced entirely
    /// by the CLI that owns the local destination.
    Get {
        host: String,
        remote_path: String,
        local_path: String,
        #[serde(default)]
        session: Option<String>,
        #[serde(default)]
        lease_token: Option<String>,
    },
    /// Open a `-L` (local) or `-R` (remote/reverse) port forward through
    /// `host` (DESIGN.md §6). `direction` carries the raw OpenSSH-style spec
    /// string exactly as typed (`[bind_addr:]port:host:port` shape); the
    /// daemon owns parsing it (`daemon::forward::parse_local_spec` /
    /// `parse_remote_spec`) so the error message stays daemon-side "teaching
    /// material" (DESIGN.md §7) rather than duplicated in the CLI. Gated by
    /// the same lease as `Run`/`Open` (DESIGN.md §4) — creating a forward is
    /// live network access to `host`.
    Forward {
        host: String,
        direction: ForwardDirection,
        #[serde(default)]
        lease_token: Option<String>,
    },
    /// List active forwards (DESIGN.md §6). Not gated by a lease, same as
    /// `Ls`/`Status` — read-only.
    ForwardLs,
    /// Stop an active forward (DESIGN.md §6). Not gated by a lease:
    /// stopping only ever *reduces* access, never grants it.
    ForwardStop { id: String },
}

impl Request {
    /// Stable, field-free request name for diagnostics. Logging a full
    /// request would expose lease tokens, interactive keystrokes, and file
    /// payloads.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Status => "Status",
            Self::Hello { .. } => "Hello",
            Self::Shutdown => "Shutdown",
            Self::Run { .. } => "Run",
            Self::Peek { .. } => "Peek",
            Self::Send { .. } => "Send",
            Self::Interrupt { .. } => "Interrupt",
            Self::Open { .. } => "Open",
            Self::Ls { .. } => "Ls",
            Self::Kill { .. } => "Kill",
            Self::RequestLease { .. } => "RequestLease",
            Self::DescribeLeaseRequest { .. } => "DescribeLeaseRequest",
            Self::ApproveLease { .. } => "ApproveLease",
            Self::VaultExists => "VaultExists",
            Self::InitVault { .. } => "InitVault",
            Self::AddCred { .. } => "AddCred",
            Self::RmCred { .. } => "RmCred",
            Self::Put { .. } => "Put",
            Self::Get { .. } => "Get",
            Self::Forward { .. } => "Forward",
            Self::ForwardLs => "ForwardLs",
            Self::ForwardStop { .. } => "ForwardStop",
        }
    }
}

/// Which side of a forward is doing the listening, carrying the raw spec
/// string for that direction (DESIGN.md §6). A newtype-per-variant rather
/// than a shared `spec: String` + separate `is_remote: bool` field, so a
/// malformed wire message can never claim both/neither direction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ForwardDirection {
    /// `-L [bind_addr:]local_port:remote_host:remote_port`.
    Local { spec: String },
    /// `-R [bind_addr:]remote_port:local_host:local_port`.
    Remote { spec: String },
}

fn default_run_timeout_secs() -> u64 {
    60
}

/// A response sent from the daemon back to the CLI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Response {
    /// Reply to `Request::Status`.
    Status(StatusReply),
    /// The daemon accepted `Request::Hello`; ordinary requests may follow on
    /// this connection.
    ProtocolReady { wire_protocol: u32 },
    /// Reply to `Request::Run`.
    Run(RunReply),
    /// Reply to `Request::Peek`.
    Peek(PeekReply),
    /// Reply to `Request::Ls`. A struct variant (not a newtype around a
    /// `Vec`) because internally-tagged enums (`#[serde(tag = "type")]`)
    /// require every variant to serialize as a JSON object, and a bare
    /// sequence can't carry the injected `"type"` field.
    Ls { sessions: Vec<SessionSummary> },
    /// Reply to `Request::Open` (and usable for any op that hands back a
    /// single session's current summary).
    Session(SessionSummary),
    /// Generic acknowledgement (e.g. for `Request::Shutdown`, `Send`,
    /// `Interrupt`, `Kill`, and an idempotent `RequestLease` hit).
    Ok,
    /// The request was understood but could not be satisfied.
    Error { message: String },
    /// Reply to `Request::RequestLease` (new pending request) and
    /// `Request::DescribeLeaseRequest`.
    LeaseRequestPending(LeaseRequestSummary),
    /// Reply to `Request::VaultExists`.
    VaultExists { exists: bool },
    /// Reply to `Request::ApproveLease`.
    LeaseActivated(LeaseActivatedInfo),
    /// Reply to `Request::Put`/`Request::Get`.
    Transfer(TransferReply),
    /// SFTP endpoint is open. The sender may start raw frame streaming on the
    /// same channel; zero-length frame terminates the byte stream.
    TransferReady,
    /// Reply to `Request::Forward`: the daemon prints this and the CLI
    /// exits — the forward itself keeps running in the daemon.
    Forward(ForwardOpened),
    /// Reply to `Request::ForwardLs`.
    ForwardLs { forwards: Vec<ForwardSummary> },
}

/// Reply to `Request::Run`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RunReply {
    pub host: String,
    pub session: String,
    /// `"done"` | `"running"` | `"dead"` (DESIGN.md §3).
    pub state: String,
    /// Only set when `state == "done"`.
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// Shaped (ANSI-stripped unless `--raw`) tail of the command's output.
    pub output: String,
    /// True if `output` was truncated to the ~30k char cap (DESIGN.md §5).
    #[serde(default)]
    pub truncated: bool,
    /// Total bytes produced by this run (before truncation), for sizing
    /// follow-up `grep`/`tail` against the spool file.
    #[serde(default)]
    pub total_bytes: u64,
    /// Path to the full, untruncated output on disk (DESIGN.md §5).
    pub spool_path: String,
    /// Only set when `state == "dead"`.
    #[serde(default)]
    pub dead_reason: Option<String>,
}

/// Reply to `Request::Peek`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PeekReply {
    pub host: String,
    pub session: String,
    /// `"idle"` | `"busy"` | `"dead"`.
    pub state: String,
    pub output: String,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub total_bytes: u64,
    #[serde(default)]
    pub dead_reason: Option<String>,
}

/// Daemon health snapshot returned by `Request::Status`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StatusReply {
    pub pid: u32,
    pub version: String,
    /// Exact wire contract spoken by the daemon. Missing means a legacy
    /// daemon that predates protocol negotiation and therefore cannot safely
    /// be used by a current CLI.
    #[serde(default)]
    pub wire_protocol: u32,
    pub uptime_secs: u64,
    /// Live PTY sessions. Empty until session management lands.
    #[serde(default)]
    pub sessions: Vec<SessionSummary>,
    /// Active authorization leases. Empty until lease management lands.
    #[serde(default)]
    pub leases: Vec<LeaseSummary>,
}

/// One-line summary of a live session, for `status`/`ls`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub name: String,
    pub host: String,
    /// `"idle"` | `"busy"` | `"dead"`.
    pub state: String,
    /// Seconds since the session last saw a read or write (DESIGN.md §3
    /// idle-reaping clock).
    #[serde(default)]
    pub idle_secs: u64,
    /// Only set when `state == "dead"`.
    #[serde(default)]
    pub dead_reason: Option<String>,
}

/// One-line summary of an active lease, for `status`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LeaseSummary {
    pub hosts: Vec<String>,
    /// Human-meaningful name of the anchor process (e.g. `"claude"`), if its
    /// executable basename could be resolved.
    #[serde(default)]
    pub anchor_name: Option<String>,
    pub anchor_pid: u32,
    /// Seconds remaining before this lease is dropped for inactivity
    /// (DESIGN.md §4 idle timeout).
    pub idle_remaining_secs: u64,
}

/// Details of a pending (unapproved) or just-created lease request, shown to
/// the human running `sloosh approve` before they enter their master
/// password.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LeaseRequestSummary {
    pub id: String,
    pub hosts: Vec<String>,
    #[serde(default)]
    pub anchor_name: Option<String>,
    pub anchor_pid: u32,
    pub age_secs: u64,
    /// Whether a vault already exists — if not, the request cannot be
    /// approved until a human runs `sloosh vault init` (approval never
    /// creates the vault; that would allow self-approval on a fresh
    /// install).
    pub vault_exists: bool,
}

/// A newly-activated lease, returned once from `sloosh approve`'s reply.
/// `token` is the `SLOOSH_LEASE` escape-hatch value (DESIGN.md §4) — it is
/// deliberately surfaced ONLY here, in this one confirmation output, and
/// nowhere else (not in `status`, not logged).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LeaseActivatedInfo {
    pub hosts: Vec<String>,
    #[serde(default)]
    pub anchor_name: Option<String>,
    pub anchor_pid: u32,
    pub token: String,
    /// Granted hosts that have no recorded key in either known_hosts file,
    /// resolved by the daemon to their real endpoints (vault entry first,
    /// then `~/.ssh/config`, then the alias as a literal hostname) so the
    /// CLI can dial each one for the fingerprint-confirmation prompt. The
    /// endpoint is not a secret — only the vault's *password* stays
    /// daemon-side.
    #[serde(default)]
    pub unverified_hosts: Vec<UnverifiedHostKey>,
}

/// Reply to `Request::Put`/`Request::Get` (DESIGN.md §5-6).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TransferReply {
    pub host: String,
    pub session: String,
    pub local_path: String,
    pub remote_path: String,
    pub bytes_transferred: u64,
}

/// Reply to `Request::Forward` once the daemon has bound the local listener
/// (`-L`) or registered the remote listen request (`-R`) and the tunnel is
/// live (DESIGN.md §6).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ForwardOpened {
    /// Short `fwd-`-prefixed id (`daemon::forward`), used by `forward stop`.
    pub id: String,
    pub host: String,
    /// `"L"` or `"R"`.
    pub direction: String,
    /// The raw spec as given on the command line.
    pub spec: String,
    /// Where traffic actually enters the tunnel: the local bind address for
    /// `-L`, or `bind_addr:remote_port` on `host` for `-R`. Reported instead
    /// of echoing the requested port because `local_port`/`remote_port` `0`
    /// asks for an OS-assigned port (DESIGN.md §6).
    pub listen_addr: String,
}

/// One-line summary of an active forward, for `forward ls`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ForwardSummary {
    pub id: String,
    pub host: String,
    /// `"L"` or `"R"`.
    pub direction: String,
    pub spec: String,
    /// Number of currently-open tunneled connections (not cumulative).
    pub tunnel_count: usize,
    pub age_secs: u64,
}

/// One granted host that still needs its host key fetched, shown to the
/// human, and recorded (`~/.sloosh/known_hosts`) during `sloosh approve`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnverifiedHostKey {
    /// The alias as requested/granted (what the agent passes to `run` etc.).
    pub host: String,
    /// Resolved address actually dialed.
    pub hostname: String,
    pub port: u16,
}

/// Serialize `msg` as one JSON line and write it, flushing so the peer sees
/// it immediately (NDJSON framing: exactly one `\n`-terminated object).
pub async fn write_message<W, T>(writer: &mut W, msg: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut line =
        serde_json::to_string(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    line.push('\n');
    if line.len() > MAX_WIRE_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "wire message is {} bytes, exceeds {} byte limit",
                line.len(),
                MAX_WIRE_MESSAGE_BYTES
            ),
        ));
    }
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await
}

/// Read one NDJSON line and deserialize it. Returns `Ok(None)` on clean EOF
/// (peer closed the connection between messages).
pub async fn read_message<R, T>(reader: &mut R) -> io::Result<Option<T>>
where
    R: AsyncBufRead + Unpin,
    T: DeserializeOwned,
{
    read_message_with_limit(reader, MAX_WIRE_MESSAGE_BYTES).await
}

async fn read_message_with_limit<R, T>(reader: &mut R, limit: usize) -> io::Result<Option<T>>
where
    R: AsyncBufRead + Unpin,
    T: DeserializeOwned,
{
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            break;
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let take = newline.map_or(available.len(), |i| i + 1);
        if line.len().saturating_add(take) > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("wire message exceeds {limit} byte limit"),
            ));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            break;
        }
    }

    while matches!(line.last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
    if line.is_empty() {
        return Ok(None);
    }
    serde_json::from_slice(&line)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T>(value: T)
    where
        T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_string(&value).expect("serialize");
        let back: T = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(value, back);
    }

    #[test]
    fn request_status_round_trips() {
        round_trip(Request::Status);
    }

    #[test]
    fn protocol_handshake_round_trips() {
        round_trip(Request::Hello {
            wire_protocol: WIRE_PROTOCOL_VERSION,
        });
        round_trip(Response::ProtocolReady {
            wire_protocol: WIRE_PROTOCOL_VERSION,
        });
    }

    #[test]
    fn request_shutdown_round_trips() {
        round_trip(Request::Shutdown);
    }

    #[test]
    fn response_status_round_trips() {
        round_trip(Response::Status(StatusReply {
            pid: 1234,
            version: "0.1.0".to_string(),
            wire_protocol: WIRE_PROTOCOL_VERSION,
            uptime_secs: 42,
            sessions: vec![SessionSummary {
                name: "default".to_string(),
                host: "example".to_string(),
                state: "running".to_string(),
                idle_secs: 5,
                dead_reason: None,
            }],
            leases: vec![LeaseSummary {
                hosts: vec!["example".to_string()],
                anchor_name: Some("claude".to_string()),
                anchor_pid: 42,
                idle_remaining_secs: 3600,
            }],
        }));
    }

    #[test]
    fn response_ok_and_error_round_trip() {
        round_trip(Response::Ok);
        round_trip(Response::Error {
            message: "boom".to_string(),
        });
    }

    #[test]
    fn old_status_reply_without_new_fields_still_parses() {
        // Simulates a future client dropping newly-added fields entirely;
        // #[serde(default)] must keep this backward compatible.
        let json = r#"{"pid":1,"version":"0.0.1","uptime_secs":0}"#;
        let reply: StatusReply = serde_json::from_str(json).expect("deserialize");
        assert_eq!(reply.wire_protocol, 0);
        assert!(reply.sessions.is_empty());
        assert!(reply.leases.is_empty());
    }

    #[test]
    fn request_tag_is_stable() {
        let json = serde_json::to_string(&Request::Status).unwrap();
        assert_eq!(json, r#"{"type":"Status"}"#);
    }

    #[test]
    fn request_run_round_trips_with_defaults() {
        round_trip(Request::Run {
            host: "box".to_string(),
            command: "ls".to_string(),
            session: None,
            timeout_secs: default_run_timeout_secs(),
            raw: false,
            lease_token: None,
        });
        // An old client omitting the newer fields entirely must still parse
        // and pick up the 60s default (DESIGN.md §5 / #[serde(default)] discipline).
        let json = r#"{"type":"Run","host":"box","command":"ls"}"#;
        let req: Request = serde_json::from_str(json).expect("deserialize");
        assert_eq!(
            req,
            Request::Run {
                host: "box".to_string(),
                command: "ls".to_string(),
                session: None,
                timeout_secs: 60,
                raw: false,
                lease_token: None,
            }
        );
    }

    #[test]
    fn request_peek_send_interrupt_open_ls_kill_round_trip() {
        round_trip(Request::Peek {
            host: "box".to_string(),
            session: Some("dev".to_string()),
            tail: Some(100),
            raw: true,
            lease_token: None,
        });
        round_trip(Request::Send {
            host: "box".to_string(),
            keys: "y".to_string(),
            session: None,
            newline: true,
            lease_token: Some("deadbeef".to_string()),
        });
        round_trip(Request::Interrupt {
            host: "box".to_string(),
            session: None,
            lease_token: None,
        });
        round_trip(Request::Open {
            host: "box".to_string(),
            name: "dev".to_string(),
            lease_token: None,
        });
        round_trip(Request::Ls { host: None });
        round_trip(Request::Kill {
            host: "box".to_string(),
            session: Some("dev".to_string()),
            lease_token: None,
        });
    }

    #[test]
    fn old_run_request_without_lease_token_still_parses() {
        // Backward compat: a client built before the vault/lease milestone
        // omits `lease_token` entirely; `#[serde(default)]` must fill it in
        // as `None` rather than failing to parse.
        let json = r#"{"type":"Send","host":"box","keys":"y"}"#;
        let req: Request = serde_json::from_str(json).expect("deserialize");
        assert_eq!(
            req,
            Request::Send {
                host: "box".to_string(),
                keys: "y".to_string(),
                session: None,
                newline: false,
                lease_token: None,
            }
        );
    }

    #[test]
    fn request_lease_flow_round_trips() {
        round_trip(Request::RequestLease {
            hosts: vec!["web".to_string(), "db".to_string()],
        });
        round_trip(Request::DescribeLeaseRequest {
            id: "ABCD1234".to_string(),
        });
        round_trip(Request::ApproveLease {
            id: "ABCD1234".to_string(),
            master_password: SecretString::new("hunter2"),
            approved_hosts: vec!["web".to_string(), "bastion".to_string()],
        });
        round_trip(Request::VaultExists);
        round_trip(Request::InitVault {
            master_password: SecretString::new("hunter2"),
        });
    }

    #[test]
    fn forward_requests_and_responses_round_trip() {
        round_trip(Request::Forward {
            host: "box".to_string(),
            direction: ForwardDirection::Local {
                spec: "8080:127.0.0.1:80".to_string(),
            },
            lease_token: None,
        });
        round_trip(Request::Forward {
            host: "box".to_string(),
            direction: ForwardDirection::Remote {
                spec: "9000:127.0.0.1:3000".to_string(),
            },
            lease_token: Some("deadbeef".to_string()),
        });
        round_trip(Request::ForwardLs);
        round_trip(Request::ForwardStop {
            id: "fwd-abc123".to_string(),
        });
        round_trip(Response::Forward(ForwardOpened {
            id: "fwd-abc123".to_string(),
            host: "box".to_string(),
            direction: "L".to_string(),
            spec: "8080:127.0.0.1:80".to_string(),
            listen_addr: "127.0.0.1:8080".to_string(),
        }));
        round_trip(Response::ForwardLs {
            forwards: vec![ForwardSummary {
                id: "fwd-abc123".to_string(),
                host: "box".to_string(),
                direction: "L".to_string(),
                spec: "8080:127.0.0.1:80".to_string(),
                tunnel_count: 2,
                age_secs: 30,
            }],
        });
    }

    #[test]
    fn old_forward_request_without_lease_token_still_parses() {
        // Backward compat, same discipline as the other requests: a client
        // built before `lease_token` existed on this request must still parse.
        let json = r#"{"type":"Forward","host":"box","direction":{"type":"Local","spec":"8080:127.0.0.1:80"}}"#;
        let req: Request = serde_json::from_str(json).expect("deserialize");
        assert_eq!(
            req,
            Request::Forward {
                host: "box".to_string(),
                direction: ForwardDirection::Local {
                    spec: "8080:127.0.0.1:80".to_string(),
                },
                lease_token: None,
            }
        );
    }

    #[test]
    fn credential_enrollment_requests_round_trip() {
        round_trip(Request::AddCred {
            alias: "web".to_string(),
            hostname: "example.com".to_string(),
            port: Some(22),
            user: Some("alice".to_string()),
            ssh_password: SecretString::new("sshpw"),
            master_password: SecretString::new("masterpw"),
            replace: false,
            jump: Some("bastion".to_string()),
        });
        round_trip(Request::RmCred {
            alias: "web".to_string(),
            master_password: SecretString::new("masterpw"),
        });
    }

    #[test]
    fn old_add_cred_without_jump_still_parses() {
        // Backward compat: a client built before the ProxyJump-chain
        // milestone omits `jump` entirely; `#[serde(default)]` must fill it
        // in as `None` rather than failing to parse.
        let json = r#"{"type":"AddCred","alias":"web","hostname":"example.com",
            "ssh_password":"sshpw","master_password":"masterpw"}"#;
        let req: Request = serde_json::from_str(json).expect("deserialize");
        assert_eq!(
            req,
            Request::AddCred {
                alias: "web".to_string(),
                hostname: "example.com".to_string(),
                port: None,
                user: None,
                ssh_password: SecretString::new("sshpw"),
                master_password: SecretString::new("masterpw"),
                replace: false,
                jump: None,
            }
        );
    }

    #[test]
    fn secret_string_debug_never_reveals_the_secret() {
        let secret = SecretString::new("hunter2");
        let debug = format!("{secret:?}");
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(debug.contains("redacted"), "{debug}");

        // The whole point of wrapping password fields in `SecretString`:
        // deriving `Debug` on a `Request` variant that embeds one must not
        // leak it either, since `daemon/mod.rs` logs `debug!(?req, ...)` for
        // every inbound message.
        let req = Request::ApproveLease {
            id: "X".to_string(),
            master_password: SecretString::new("super-secret-password"),
            approved_hosts: vec!["web".to_string()],
        };
        let debug = format!("{req:?}");
        assert!(!debug.contains("super-secret-password"), "{debug}");
    }

    #[test]
    fn old_approve_request_defaults_to_empty_for_fail_closed_check() {
        let json = r#"{"type":"ApproveLease","id":"ABCD1234","master_password":"hunter2"}"#;
        let req: Request = serde_json::from_str(json).expect("deserialize");
        assert_eq!(
            req,
            Request::ApproveLease {
                id: "ABCD1234".to_string(),
                master_password: SecretString::new("hunter2"),
                approved_hosts: Vec::new(),
            }
        );
    }

    #[test]
    fn lease_response_variants_round_trip() {
        round_trip(Response::LeaseRequestPending(LeaseRequestSummary {
            id: "ABCD1234".to_string(),
            hosts: vec!["web".to_string()],
            anchor_name: Some("claude".to_string()),
            anchor_pid: 42,
            age_secs: 5,
            vault_exists: true,
        }));
        round_trip(Response::VaultExists { exists: false });
        round_trip(Response::LeaseActivated(LeaseActivatedInfo {
            hosts: vec!["web".to_string()],
            anchor_name: Some("claude".to_string()),
            anchor_pid: 42,
            token: "deadbeef".to_string(),
            unverified_hosts: vec![UnverifiedHostKey {
                host: "web".to_string(),
                hostname: "web.internal.example".to_string(),
                port: 22,
            }],
        }));
    }

    #[test]
    fn old_lease_activated_without_unverified_hosts_still_parses() {
        // Backward compat: a daemon built before the approve-side host-key
        // resolution omits `unverified_hosts`; `#[serde(default)]` fills it
        // in as empty rather than failing to parse.
        let json = r#"{"hosts":["web"],"anchor_pid":42,"token":"deadbeef"}"#;
        let info: LeaseActivatedInfo = serde_json::from_str(json).expect("deserialize");
        assert!(info.unverified_hosts.is_empty());
        assert_eq!(info.anchor_name, None);
    }

    #[test]
    fn response_run_peek_ls_session_round_trip() {
        round_trip(Response::Run(RunReply {
            host: "box".to_string(),
            session: "default".to_string(),
            state: "done".to_string(),
            exit_code: Some(0),
            output: "hi\n".to_string(),
            truncated: false,
            total_bytes: 3,
            spool_path: "/home/u/.sloosh/spool/box--default/000001.log".to_string(),
            dead_reason: None,
        }));
        round_trip(Response::Peek(PeekReply {
            host: "box".to_string(),
            session: "default".to_string(),
            state: "idle".to_string(),
            output: String::new(),
            truncated: false,
            total_bytes: 0,
            dead_reason: None,
        }));
        round_trip(Response::Ls {
            sessions: vec![SessionSummary {
                name: "default".to_string(),
                host: "box".to_string(),
                state: "idle".to_string(),
                idle_secs: 12,
                dead_reason: None,
            }],
        });
        round_trip(Response::Session(SessionSummary {
            name: "dev".to_string(),
            host: "box".to_string(),
            state: "idle".to_string(),
            idle_secs: 0,
            dead_reason: None,
        }));
    }

    #[test]
    fn put_get_requests_carry_labels_not_local_file_authority() {
        round_trip(Request::Put {
            host: "box".to_string(),
            local_path: "/home/u/file.txt".to_string(),
            remote_path: "/tmp/file.txt".to_string(),
            session: None,
            lease_token: None,
        });
        round_trip(Request::Get {
            host: "box".to_string(),
            remote_path: "/tmp/file.txt".to_string(),
            local_path: "/home/u/file.txt".to_string(),
            session: Some("dev".to_string()),
            lease_token: Some("deadbeef".to_string()),
        });
    }

    #[test]
    fn transfer_reply_round_trips() {
        let reply = TransferReply {
            host: "box".to_string(),
            session: "default".to_string(),
            local_path: "/home/u/file.txt".to_string(),
            remote_path: "/tmp/file.txt".to_string(),
            bytes_transferred: 1234,
        };
        round_trip(Response::Transfer(reply.clone()));
        round_trip(Response::TransferReady);
    }

    #[tokio::test]
    async fn oversized_wire_message_is_rejected_before_unbounded_growth() {
        let input = b"{\"type\":\"Status\",\"padding\":\"xxxxxxxx\"}\n";
        let mut reader = tokio::io::BufReader::new(&input[..]);
        let err = read_message_with_limit::<_, Request>(&mut reader, 16)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds"));
    }
}
