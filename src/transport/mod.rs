//! Local IPC transport abstraction (docs/internals/architecture.md).
//!
//! Platform differences in how a connected peer's identity is recovered
//! (`SO_PEERCRED` on Linux, `LOCAL_PEERPID` on macOS, `GetNamedPipeClientProcessId`
//! on Windows in phase 2) must never leak into caller code — they are
//! confined to one file per platform (`unix.rs`; `windows.rs` later) behind
//! the [`Channel`] trait. Connect/bind are plain functions in that same
//! per-platform module rather than trait methods, since a future Windows
//! implementation swaps the whole module, not a generic parameter.

pub mod unix;

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::future::Future;
use std::io;

/// Maximum payload in one raw stream frame. Streams may contain any number
/// of frames, so this bounds per-allocation memory without limiting total
/// transfer size.
pub const MAX_RAW_FRAME_BYTES: usize = 1024 * 1024;

/// A connected local IPC channel, client or server side.
///
/// Lease anchoring (docs/internals/architecture.md) depends on knowing which process is on the
/// other end of the socket, so `peer_pid` is the one operation every
/// transport implementation must provide.
pub trait Channel: Send {
    /// PID of the process on the other end of this channel, if the platform
    /// exposes it. `Ok(None)` means the platform has no such facility;
    /// `Err` means the lookup itself failed (e.g. the peer already exited).
    fn peer_pid(&self) -> io::Result<Option<u32>>;

    /// Write one NDJSON message.
    fn send<T>(&mut self, msg: &T) -> impl Future<Output = io::Result<()>> + Send
    where
        T: Serialize + Sync;

    /// Read one NDJSON message. `Ok(None)` means the peer closed the
    /// connection cleanly between messages.
    fn recv<T>(&mut self) -> impl Future<Output = io::Result<Option<T>>> + Send
    where
        T: DeserializeOwned;

    /// Write one raw stream frame after an NDJSON message. Wire format is a
    /// four-byte big-endian unsigned length followed by that many bytes. A
    /// zero-length frame marks end-of-stream.
    fn send_raw_frame(&mut self, frame: &[u8]) -> impl Future<Output = io::Result<()>> + Send;

    /// Read one raw stream frame from the same buffered reader used by
    /// [`Channel::recv`]. `Ok(None)` is the zero-length end-of-stream frame;
    /// transport EOF remains an error.
    fn recv_raw_frame(&mut self) -> impl Future<Output = io::Result<Option<Vec<u8>>>> + Send;
}

/// Outcome of trying to bind the well-known socket path.
pub enum BindOutcome<L> {
    /// This process now owns the socket and should run the accept loop.
    Bound(L),
    /// Another daemon already owns the socket; the caller should exit
    /// quietly rather than treat this as an error (see docs/internals/architecture.md: bind
    /// atomicity resolves the concurrent-auto-spawn race).
    AlreadyRunning,
}
