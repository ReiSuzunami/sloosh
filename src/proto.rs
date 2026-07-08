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
}

/// A response sent from the daemon back to the CLI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Response {
    /// Reply to `Request::Status`.
    Status(StatusReply),
    /// Generic acknowledgement (e.g. for `Request::Shutdown`).
    Ok,
    /// The request was understood but could not be satisfied.
    Error { message: String },
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
    pub state: String,
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
}
