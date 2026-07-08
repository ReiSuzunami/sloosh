//! Local IPC transport abstraction (DESIGN.md §2, §8).
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

/// A connected local IPC channel, client or server side.
///
/// Lease anchoring (DESIGN.md §4) depends on knowing which process is on the
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
}

/// Outcome of trying to bind the well-known socket path.
pub enum BindOutcome<L> {
    /// This process now owns the socket and should run the accept loop.
    Bound(L),
    /// Another daemon already owns the socket; the caller should exit
    /// quietly rather than treat this as an error (see DESIGN.md §1: bind
    /// atomicity resolves the concurrent-auto-spawn race).
    AlreadyRunning,
}
