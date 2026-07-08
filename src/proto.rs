//! NDJSON wire protocol between the `sloosh` CLI and `sloosh daemon`.
//!
//! Every message is a single JSON object serialized on one line (newline
//! delimited JSON), so the protocol stays debuggable with `nc -U` and never
//! needs a schema compiler. Enums are internally tagged (`"type"` field) so
//! new variants and fields can be added without breaking older peers —
//! unknown fields are ignored by serde by default, and `#[serde(default)]`
//! lets old messages satisfy newly-added fields.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

/// A request sent from the CLI to the daemon.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Request {
    /// Report daemon health: pid, version, uptime, live sessions and leases.
    Status,
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
    },
    /// Write raw bytes/keystrokes to a session's PTY.
    Send {
        host: String,
        keys: String,
        #[serde(default)]
        session: Option<String>,
        #[serde(default)]
        newline: bool,
    },
    /// Send Ctrl-C (0x03) to a session's PTY.
    Interrupt {
        host: String,
        #[serde(default)]
        session: Option<String>,
    },
    /// Explicitly open (create-or-reuse) a named parallel session on a host.
    Open { host: String, name: String },
    /// List known sessions, optionally filtered by host.
    Ls {
        #[serde(default)]
        host: Option<String>,
    },
    /// Kill a session, terminating the remote shell.
    Kill {
        host: String,
        #[serde(default)]
        session: Option<String>,
    },
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
    /// `Interrupt`, `Kill`).
    Ok,
    /// The request was understood but could not be satisfied.
    Error { message: String },
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
    pub host: String,
    pub expires_in_secs: u64,
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
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(None);
    }
    let trimmed = line.trim_end();
    if trimmed.is_empty() {
        return Ok(None);
    }
    serde_json::from_str(trimmed)
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
    fn request_shutdown_round_trips() {
        round_trip(Request::Shutdown);
    }

    #[test]
    fn response_status_round_trips() {
        round_trip(Response::Status(StatusReply {
            pid: 1234,
            version: "0.1.0".to_string(),
            uptime_secs: 42,
            sessions: vec![SessionSummary {
                name: "default".to_string(),
                host: "example".to_string(),
                state: "running".to_string(),
                idle_secs: 5,
                dead_reason: None,
            }],
            leases: vec![LeaseSummary {
                host: "example".to_string(),
                expires_in_secs: 3600,
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
        });
        round_trip(Request::Send {
            host: "box".to_string(),
            keys: "y".to_string(),
            session: None,
            newline: true,
        });
        round_trip(Request::Interrupt {
            host: "box".to_string(),
            session: None,
        });
        round_trip(Request::Open {
            host: "box".to_string(),
            name: "dev".to_string(),
        });
        round_trip(Request::Ls { host: None });
        round_trip(Request::Kill {
            host: "box".to_string(),
            session: Some("dev".to_string()),
        });
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
}
