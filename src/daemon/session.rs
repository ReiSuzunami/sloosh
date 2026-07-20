//! Persistent PTY session management: sentinel-based command/output framing,
//! ring buffer + cursor `peek`, spool-to-disk, dead-session semantics, idle
//! reaping (docs/internals/architecture.md).
//!
//! Same interim trust posture as the rest of the daemon (see the note in
//! `daemon/mod.rs`): any local caller can address any session. No
//! per-session authorization is enforced here yet.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
#[cfg(test)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::sync::Mutex;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rand::Rng;
use russh_sftp::client::error::Error as SftpClientError;
use russh_sftp::client::fs::File as SftpFile;
use russh_sftp::client::{Config as SftpConfig, SftpSession};
use russh_sftp::protocol::{OpenFlags, StatusCode};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{Mutex as AsyncMutex, watch};
use tokio::time::sleep_until;
use tracing::{info, warn};

use crate::daemon::audit;
use crate::daemon::ssh::{self, SshError};
use crate::proto::{SessionSummary, TransferReply};

mod spool;

#[cfg(test)]
use spool::{
    MAX_ENCODED_SPOOL_NAME_BYTES, MAX_SPOOL_DIR_BYTES, MAX_SPOOL_FILE_BYTES, MAX_SPOOL_ROOT_BYTES,
    SPOOL_LIMIT_MARKER, SpoolLedger, cleanup_spool_dir_preserving, cleanup_spool_root,
    encode_spool_name, ensure_private_dir, lock_spool_ledger, open_spool_file_under,
    spool_dir_under, spool_ledger,
};
use spool::{SpoolWriter, open_spool_file};

/// Bound on how much output we keep in memory per session (`SECURITY.md`).
const RING_CAPACITY: usize = 256 * 1024;
/// Cap on how much of a single run/peek reply's `output` field we send back
/// (`SECURITY.md`); spool persistence has separate bounded per-run and global
/// budgets below.
const MAX_OUTPUT_CHARS: usize = 30_000;
/// Replace russh-sftp's 10-second request deadline with the maximum value.
/// In the pinned Tokio release this maps to its roughly 30-year far-future
/// timer: operationally disabled for NAS transfers, though not mathematical
/// infinity. Transport/server failures still surface normally.
const SFTP_REQUEST_TIMEOUT_SECS: u64 = u64::MAX;
/// A session with no read or write activity for this long is reaped
/// (docs/internals/architecture.md). Configurable only in the sense that it's one constant to
/// edit — no config surface for it in this milestone.
const IDLE_REAP_AFTER: Duration = Duration::from_secs(8 * 60 * 60);
/// How often the idle reaper wakes up to check.
const IDLE_REAP_SWEEP_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// How long `open`/first `run` waits for the shell-init frame's marker
/// (banner consumption, D2) before giving up and proceeding degraded.
const SESSION_READY_TIMEOUT: Duration = Duration::from_secs(15);

/// Shell-quiescing commands sent (framed with their own sentinel) as the
/// first line of every new session:
/// - `stty -echo` turns off tty-driver echo even if the server ignored the
///   ECHO=0 PTY mode we request in `ssh.rs`;
/// - `set +o emacs` / `set +o vi` disable readline/zle line editing, which
///   otherwise re-echoes input *itself*, regardless of tty echo settings —
///   this was the actual source of command echoes observed live;
/// - the rest disables color, prompts, and history so nothing but real
///   command output shows up.
const INIT_COMMANDS: &str = "stty -echo 2>/dev/null; set +o emacs 2>/dev/null; \
     set +o vi 2>/dev/null; export NO_COLOR=1 TERM=dumb; unset HISTFILE; \
     PS1='' PROMPT_COMMAND=''";

/// Everything that can go wrong operating on a session. Self-teaching
/// messages per docs/internals/architecture.md.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(
        "no session '{session}' on '{host}' — run `sloosh run {host} <command>` (creates the \
         default session) or `sloosh open {host} {session}` first"
    )]
    NotFound { host: String, session: String },

    #[error(
        "session '{session}' on '{host}' is still busy running a previous command — `sloosh peek \
         {host} --session {session}` to check on it and wait for it to finish. If it stays busy \
         (e.g. a command that survived an interrupt, or a wedged shell), `sloosh kill {host} \
         --session {session}` and reopen it"
    )]
    Busy { host: String, session: String },

    #[error(
        "session '{session}' on '{host}' is dead ({reason}); sloosh never reconnects \
         automatically — run `sloosh kill {host} --session {session}` then reopen it"
    )]
    Dead {
        host: String,
        session: String,
        reason: String,
    },

    #[error(transparent)]
    Ssh(#[from] SshError),

    #[error(
        "could not write the session's spool file under ~/.sloosh/spool — check that the \
         directory exists and is writable by this user. (io: {0})"
    )]
    Io(#[from] std::io::Error),

    // -- put/get (docs/internals/architecture.md) -------------------------------------------
    #[error(
        "local file '{path}' does not exist or is not readable — check the path (`sloosh put` \
         resolves relative paths from the directory it's run in, since the daemon's own working \
         directory is not yours). (io: {source})"
    )]
    LocalFileMissing {
        path: String,
        source: std::io::Error,
    },

    #[error(
        "local destination '{path}' already exists — `sloosh get` refuses to overwrite a file \
         on your machine unless you pass --force. (Overwriting the *remote* file on `put` is \
         always allowed: the remote host is the disposable workspace; your local machine is not, \
         so `get` is more careful about it.) Pass --force to overwrite it, or choose a different \
         local path."
    )]
    LocalDestinationExists { path: String },

    #[error(
        "could not write local destination '{path}' — check that its containing directory \
         exists and is writable by this user. (io: {source})"
    )]
    LocalDestinationUnwritable {
        path: String,
        source: std::io::Error,
    },

    #[error(
        "remote path '{path}' on '{host}' over SFTP: {reason} — check the path, and that the \
         remote user has permission to reach it."
    )]
    RemotePath {
        host: String,
        path: String,
        reason: String,
    },

    #[error(
        "could not start the SFTP subsystem on '{host}' — the remote sshd may not have SFTP \
         enabled (look for a `Subsystem sftp ...` line in its sshd_config), or the connection \
         dropped mid-handshake. Try `sftp {host}` by hand to compare. (sftp: {reason})"
    )]
    Sftp { host: String, reason: String },

    #[error(
        "transfer between local '{local}' and remote '{remote}' on '{host}' failed partway \
         through — the connection may have dropped, or a disk may be full. Retry; if it keeps \
         happening, check `sloosh peek {host}` doesn't show the session as dead. (io: {source})"
    )]
    Transfer {
        host: String,
        local: String,
        remote: String,
        source: std::io::Error,
    },
}

// ---------------------------------------------------------------------------
// Ring buffer
// ---------------------------------------------------------------------------

/// Fixed-capacity byte ring buffer that also tracks the total number of
/// bytes ever pushed, so callers can address positions in "absolute stream
/// offset" space even after old bytes have been evicted.
struct RingBuffer {
    buf: VecDeque<u8>,
    cap: usize,
    total_written: u64,
}

impl RingBuffer {
    fn new(cap: usize) -> Self {
        Self {
            buf: VecDeque::with_capacity(cap.min(64 * 1024)),
            cap,
            total_written: 0,
        }
    }

    fn push_slice(&mut self, data: &[u8]) {
        // `total_written` counts every byte ever pushed, even ones that
        // never make it into `buf` because a single chunk alone exceeds
        // capacity — it's a stream position counter, not a count of what's
        // currently retained.
        self.total_written += data.len() as u64;
        // If the incoming chunk alone exceeds capacity, only its tail can
        // possibly survive; skip straight to that instead of pushing byte
        // by byte.
        let data = if data.len() > self.cap {
            &data[data.len() - self.cap..]
        } else {
            data
        };
        if self.buf.len() + data.len() > self.cap {
            let overflow = self.buf.len() + data.len() - self.cap;
            for _ in 0..overflow.min(self.buf.len()) {
                self.buf.pop_front();
            }
        }
        self.buf.extend(data.iter().copied());
    }

    /// Absolute offset of the oldest byte still held.
    fn start_offset(&self) -> u64 {
        self.total_written - self.buf.len() as u64
    }

    /// Bytes since absolute offset `cursor`. Returns `(bytes, dropped)`
    /// where `dropped` is true if `cursor` pointed at data that has already
    /// been evicted from the ring (the caller silently loses that history —
    /// documented simplification, docs/internals/architecture.md ring buffer is best-effort,
    /// not a durable log; the spool file on disk is the durable copy).
    fn since(&self, cursor: u64) -> (Vec<u8>, bool) {
        let start = self.start_offset();
        let dropped = cursor < start;
        let effective = cursor.max(start);
        let skip = (effective - start) as usize;
        (self.buf.iter().skip(skip).copied().collect(), dropped)
    }

    fn tail(&self, n: usize) -> Vec<u8> {
        let len = self.buf.len();
        let skip = len.saturating_sub(n);
        self.buf.iter().skip(skip).copied().collect()
    }
}

// ---------------------------------------------------------------------------
// Sentinel command/output framing
// ---------------------------------------------------------------------------

/// Fixed shape of every sentinel: `__sloosh_<32 lowercase hex>__`. The
/// scrubber below recognizes sentinels *by this pattern*, not by comparing
/// against a list of currently-armed sentinel strings — that way stale
/// markers (e.g. a resync probe from an interrupt whose run already
/// finished) are still scrubbed out of agent-visible output instead of
/// leaking as payload.
const SENTINEL_PREFIX: &[u8] = b"__sloosh_";
const SENTINEL_HEX_LEN: usize = 32;
const SENTINEL_SUFFIX: &[u8] = b"__";
const SENTINEL_LEN: usize = SENTINEL_PREFIX.len() + SENTINEL_HEX_LEN + SENTINEL_SUFFIX.len();
/// `$?` is 0..=255, so at most three digits between the two sentinels.
const MARKER_MAX_DIGITS: usize = 3;

/// Generate a sentinel unlikely to appear in any command's own output. Must
/// match the `SENTINEL_*` pattern constants above — the scrubber recognizes
/// sentinels by shape.
fn make_sentinel() -> String {
    let n: u128 = rand::rng().random();
    let s = format!("__sloosh_{n:032x}__");
    debug_assert_eq!(s.len(), SENTINEL_LEN);
    s
}

/// The `printf` that emits a `<sentinel><exit-code><sentinel>` marker line
/// for whatever command ran last. Used as the tail of every framed command,
/// and standalone as the resync probe after an `interrupt` (see
/// `interrupt`): sent on its own line, it reports `$?` of the interrupted
/// command line without depending on that line's own marker ever running.
fn marker_printf(sentinel: &str) -> String {
    format!("printf '\\n{sentinel}%s{sentinel}\\n' $?\n")
}

/// Build the literal line written to the PTY for one `run`: run the
/// command, then print exit status bracketed by the sentinel so the reader
/// can find where the command's own output ends (docs/internals/architecture.md).
fn frame_command(command: &str, sentinel: &str) -> String {
    format!("{command}; {}", marker_printf(sentinel))
}

/// Result of matching the raw PTY stream against the marker pattern
/// (optionally-preceding newline + `<sentinel><digits><sentinel>`).
#[derive(Debug)]
enum MarkerScan {
    /// Definitely not a marker at this position; the byte is payload.
    No,
    /// Consistent with a marker so far, but the buffer ended before it
    /// completed — hold these bytes and wait for more data.
    Partial,
    /// A complete marker: `len` bytes consumed (including any leading
    /// separator newline), plus the sentinel string and exit code found.
    Complete {
        len: usize,
        sentinel: String,
        exit_code: i32,
    },
}

/// Match `buf` (from position 0) against `<sentinel><digits><sentinel>`
/// where both sentinels must be byte-identical.
fn scan_marker(buf: &[u8]) -> MarkerScan {
    let mut i = 0;

    // First sentinel: prefix + hex + suffix.
    for &expected in SENTINEL_PREFIX {
        match buf.get(i) {
            None => return MarkerScan::Partial,
            Some(&b) if b == expected => i += 1,
            Some(_) => return MarkerScan::No,
        }
    }
    for _ in 0..SENTINEL_HEX_LEN {
        match buf.get(i) {
            None => return MarkerScan::Partial,
            Some(&(b'0'..=b'9' | b'a'..=b'f')) => i += 1,
            Some(_) => return MarkerScan::No,
        }
    }
    for &expected in SENTINEL_SUFFIX {
        match buf.get(i) {
            None => return MarkerScan::Partial,
            Some(&b) if b == expected => i += 1,
            Some(_) => return MarkerScan::No,
        }
    }
    let sentinel_end = i;

    // Exit status digits.
    let digits_start = i;
    while i < buf.len() && buf[i].is_ascii_digit() && (i - digits_start) < MARKER_MAX_DIGITS {
        i += 1;
    }
    if i == buf.len() {
        return MarkerScan::Partial;
    }
    if i == digits_start {
        return MarkerScan::No;
    }
    let digits_end = i;

    // Second sentinel, byte-identical to the first. This is what lets an
    // echoed framed command (`... printf '\n<sent>%s<sent>\n' $?`) pass as
    // ordinary bytes: its `%s` between the sentinels fails the digit check
    // above, and any lone sentinel fails here.
    for k in 0..SENTINEL_LEN {
        match buf.get(i) {
            None => return MarkerScan::Partial,
            Some(&b) if b == buf[k] => i += 1,
            Some(_) => return MarkerScan::No,
        }
    }

    let sentinel = String::from_utf8_lossy(&buf[..sentinel_end]).into_owned();
    let exit_code: i32 = std::str::from_utf8(&buf[digits_start..digits_end])
        .expect("checked ASCII digits")
        .parse()
        .expect("1..=3 ASCII digits always parse as i32");
    MarkerScan::Complete {
        len: i,
        sentinel,
        exit_code,
    }
}

/// Like `scan_marker`, but allowing the marker to be preceded by the
/// separator newline `printf` emits before it (arriving as `\r\n` through
/// the PTY, or bare `\n`/`\r`). Matching the separator as part of the
/// marker means it gets scrubbed along with it — the ring buffer receives
/// exactly the command's own output, no framing residue.
fn scan_sep_marker(buf: &[u8]) -> MarkerScan {
    let mut i = 0;
    if buf.get(i) == Some(&b'\r') {
        i += 1;
    }
    if buf.get(i) == Some(&b'\n') {
        i += 1;
    }
    if i == buf.len() {
        return MarkerScan::Partial;
    }
    match scan_marker(&buf[i..]) {
        MarkerScan::Complete {
            len,
            sentinel,
            exit_code,
        } => MarkerScan::Complete {
            len: len + i,
            sentinel,
            exit_code,
        },
        other => other,
    }
}

/// What the scrubber hands back, in stream order.
#[derive(Debug)]
enum ScrubEvent {
    /// Command/shell output with all framing internals removed.
    Payload(Vec<u8>),
    /// A complete marker was recognized (and removed from the stream).
    Marker { sentinel: String, exit_code: i32 },
}

/// Streaming scrubber sitting between the raw PTY byte stream and the ring
/// buffer / spool file: sentinel marker lines (and their surrounding
/// newlines) never reach agent-visible output — `peek` and `run` replies
/// only ever see payload (the D1 invariant: no `__sloosh_*__` line ever
/// appears in a reply).
///
/// Bytes that might be the beginning of a marker that hasn't fully arrived
/// yet are held back until the next feed resolves them, so chunk splits can
/// never leak half a sentinel (holdback is bounded by one marker's length
/// plus a couple of newline bytes).
#[derive(Debug, Default)]
struct FrameScrubber {
    /// Unresolved tail of the stream (potential partial marker).
    held: Vec<u8>,
    /// Swallow the newline `printf` emits *after* a marker, even across a
    /// chunk boundary.
    eat_newline: bool,
}

impl FrameScrubber {
    fn feed(&mut self, data: &[u8]) -> Vec<ScrubEvent> {
        let mut buf = std::mem::take(&mut self.held);
        buf.extend_from_slice(data);
        let mut events = Vec::new();
        let mut payload = Vec::new();
        let mut i = 0;
        while i < buf.len() {
            if self.eat_newline {
                if buf[i] == b'\r' {
                    i += 1;
                    continue;
                }
                self.eat_newline = false;
                if buf[i] == b'\n' {
                    i += 1;
                    continue;
                }
                // Not a newline after all: fall through, ordinary byte.
            }
            let b = buf[i];
            if matches!(b, b'\r' | b'\n' | b'_') {
                match scan_sep_marker(&buf[i..]) {
                    MarkerScan::Complete {
                        len,
                        sentinel,
                        exit_code,
                    } => {
                        if !payload.is_empty() {
                            events.push(ScrubEvent::Payload(std::mem::take(&mut payload)));
                        }
                        events.push(ScrubEvent::Marker {
                            sentinel,
                            exit_code,
                        });
                        i += len;
                        self.eat_newline = true;
                        continue;
                    }
                    MarkerScan::Partial => {
                        self.held = buf[i..].to_vec();
                        if !payload.is_empty() {
                            events.push(ScrubEvent::Payload(payload));
                        }
                        return events;
                    }
                    MarkerScan::No => {}
                }
            }
            payload.push(b);
            i += 1;
        }
        if !payload.is_empty() {
            events.push(ScrubEvent::Payload(payload));
        }
        events
    }
}

// ---------------------------------------------------------------------------
// ANSI stripping + echo suppression heuristic + truncation
// ---------------------------------------------------------------------------

/// Strip ANSI/VT escape sequences (CSI `ESC [ ... final-byte`, OSC
/// `ESC ] ... BEL/ST`, and other two-byte `ESC x` sequences). Hand-rolled
/// rather than pulling in a crate — the grammar is small and well-known.
fn strip_ansi(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != 0x1B {
            out.push(input[i]);
            i += 1;
            continue;
        }
        // ESC with nothing after it (truncated mid-stream): drop it and stop.
        let Some(&next) = input.get(i + 1) else {
            break;
        };
        match next {
            b'[' => {
                // CSI: ESC [ params... final-byte (0x40..=0x7E)
                let mut j = i + 2;
                while j < input.len() && !(0x40..=0x7E).contains(&input[j]) {
                    j += 1;
                }
                i = (j + 1).min(input.len());
            }
            b']' => {
                // OSC: ESC ] ... terminated by BEL or ESC \
                let mut j = i + 2;
                loop {
                    if j >= input.len() {
                        break;
                    }
                    if input[j] == 0x07 {
                        j += 1;
                        break;
                    }
                    if input[j] == 0x1B && input.get(j + 1) == Some(&b'\\') {
                        j += 2;
                        break;
                    }
                    j += 1;
                }
                i = j.min(input.len());
            }
            _ => {
                // Two-byte escape (e.g. charset select `ESC ( B`) — best
                // effort, consume ESC + the next byte.
                i += 2;
            }
        }
    }
    out
}

/// Defensive fallback for echo suppression: if every other layer (PTY
/// `ECHO`/`ECHONL` modes in `ssh.rs`, plus the `stty -echo` /
/// `set +o emacs` sent in `INIT_COMMANDS`) was ignored by the remote
/// shell/server, the very first line of a command's output is the shell
/// echoing the line we sent back. Strip it if it matches any of the given
/// candidates (the framed command line, or the bare command), tolerating a
/// trailing `\r` from PTY newline translation.
fn strip_echoed_command(output: &[u8], candidates: &[&str]) -> Vec<u8> {
    let first_line_end = output.iter().position(|&b| b == b'\n');
    let Some(end) = first_line_end else {
        return output.to_vec();
    };
    let mut first_line = &output[..end];
    if first_line.last() == Some(&b'\r') {
        first_line = &first_line[..first_line.len() - 1];
    }
    if candidates
        .iter()
        .any(|c| first_line == c.trim_end().as_bytes())
    {
        output[end + 1..].to_vec()
    } else {
        output.to_vec()
    }
}

/// Shape raw command output for a reply: strip ANSI (unless `raw`), then
/// cap to `MAX_OUTPUT_CHARS` (keeping the tail, since that's almost always
/// what's relevant), returning `(shown, truncated, total_bytes)` where
/// `total_bytes` is the size of the *shaped-but-untruncated* text. Spool files
/// retain up to `MAX_SPOOL_FILE_BYTES` raw bytes per run.
fn shape_output(raw: &[u8], raw_mode: bool) -> (String, bool, u64) {
    let processed = if raw_mode {
        raw.to_vec()
    } else {
        strip_ansi(raw)
    };
    let total_bytes = processed.len() as u64;
    let text = String::from_utf8_lossy(&processed).into_owned();
    let char_count = text.chars().count();
    if char_count <= MAX_OUTPUT_CHARS {
        (text, false, total_bytes)
    } else {
        let skip = char_count - MAX_OUTPUT_CHARS;
        let tail: String = text.chars().skip(skip).collect();
        let marker = format!(
            "... [truncated {skip} chars; {total_bytes} bytes total in this run — see spool file for retained output (64 MiB/run cap)] ...\n"
        );
        (marker + &tail, true, total_bytes)
    }
}

// ---------------------------------------------------------------------------
// Session state + registry
// ---------------------------------------------------------------------------

struct CurrentRun {
    sentinel: String,
    /// Armed by `interrupt` while this run is in flight: a second sentinel
    /// sent as a standalone probe line right after Ctrl-C. Whichever marker
    /// arrives first settles the run — the original sentinel (the command
    /// survived/trapped SIGINT and finished normally) or this one (the
    /// command line was aborted, so its own marker will never print).
    resync: Option<String>,
}

struct RunOutcome {
    /// `None` when the run was settled by an interrupt resync probe — the
    /// command's own exit status is unknowable at that point.
    exit_code: Option<i32>,
    /// True when the resync probe (not the command's own marker) settled
    /// the run.
    interrupted: bool,
    end_offset: u64,
}

struct SessionState {
    ring: RingBuffer,
    /// Single global read cursor for `peek` (docs/internals/architecture.md simplification:
    /// two concurrent `peek` callers on the same session share one cursor,
    /// so the second caller only sees what's new since the *first*
    /// caller's peek, not since its own last peek — documented, not fixed,
    /// for this milestone).
    cursor: u64,
    busy: bool,
    dead: Option<String>,
    last_activity: Instant,
    run_seq: u64,
    current_run: Option<CurrentRun>,
    last_result: Option<RunOutcome>,
    spool_file: Option<SpoolWriter>,
    /// Removes framing internals from the raw PTY stream before anything
    /// reaches `ring`/`spool_file`.
    scrubber: FrameScrubber,
    /// True from session open until the shell-init frame's marker arrives:
    /// everything the shell prints before then (login banner, MOTD, prompt
    /// residue, the init line's own echo) is discarded, never committed to
    /// the ring — so it can't be attributed to the first user command (D2).
    discard_until_ready: bool,
}

/// Everything needed to operate a live session. Kept alive by the registry
/// entry plus a clone held by the reader task; dropping the last `Arc`
/// drops the SSH connection (and, transitively, any single-hop `ProxyJump`
/// tunnel it was opened through).
struct SessionInner {
    host: String,
    name: String,
    write_half: Arc<ssh::ChannelWriteHalf>,
    state: AsyncMutex<SessionState>,
    /// Bumped (any change) whenever the reader task makes progress, so
    /// `run()` can wait on it instead of polling. A `watch` channel is used
    /// instead of `tokio::sync::Notify` because `Notify::notify_waiters`
    /// only wakes already-registered waiters — a `run()` call that hasn't
    /// reached the wait point yet when the sentinel arrives would miss the
    /// wakeup. `watch`'s "changed since last observed version" semantics
    /// don't have that race.
    wake_tx: watch::Sender<u64>,
    /// Held only to keep the underlying SSH connection (and its background
    /// I/O task) alive for as long as this session exists; never read.
    _connection: ssh::Connection,
}

type SessionKey = (String, String);

fn registry() -> &'static AsyncMutex<HashMap<SessionKey, Arc<SessionInner>>> {
    static REGISTRY: OnceLock<AsyncMutex<HashMap<SessionKey, Arc<SessionInner>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| AsyncMutex::new(HashMap::new()))
}

/// Drop every session from the process-global registry. A freshly started
/// daemon owns no sessions, so in a normal daemon process the registry is
/// already empty and this is a no-op — but in-process test harnesses start
/// several daemons (each on its own short-lived tokio runtime) inside one
/// test binary, and a session whose I/O tasks died with a previous test's
/// runtime must not be found by name from the next daemon.
pub async fn reset_registry() {
    registry().lock().await.clear();
}

fn default_session_name(session: Option<String>) -> String {
    session.unwrap_or_else(|| "default".to_string())
}

fn state_label(state: &SessionState) -> &'static str {
    if state.dead.is_some() {
        "dead"
    } else if state.busy {
        "busy"
    } else {
        "idle"
    }
}

fn summarize(host: &str, name: &str, state: &SessionState) -> SessionSummary {
    SessionSummary {
        name: name.to_string(),
        host: host.to_string(),
        state: state_label(state).to_string(),
        idle_secs: state.last_activity.elapsed().as_secs(),
        dead_reason: state.dead.clone(),
    }
}

/// Look up a session, erroring with a self-teaching message if it doesn't
/// exist. Does not create anything (contrast `get_or_create_session`).
async fn get_existing_session(host: &str, name: &str) -> Result<Arc<SessionInner>, SessionError> {
    let reg = registry().lock().await;
    reg.get(&(host.to_string(), name.to_string()))
        .cloned()
        .ok_or_else(|| SessionError::NotFound {
            host: host.to_string(),
            session: name.to_string(),
        })
}

/// Look up a session, creating it (opening a fresh SSH connection + PTY +
/// shell) if none exists yet. If one exists but is dead, refuses to
/// reconnect automatically (docs/internals/architecture.md) and instead returns a
/// self-teaching error telling the caller to `kill` it first.
async fn get_or_create_session(
    host: &str,
    name: &str,
    lease_ctx: &ssh::LeaseContext,
) -> Result<Arc<SessionInner>, SessionError> {
    {
        let reg = registry().lock().await;
        if let Some(existing) = reg.get(&(host.to_string(), name.to_string())) {
            let state = existing.state.lock().await;
            if let Some(reason) = &state.dead {
                return Err(SessionError::Dead {
                    host: host.to_string(),
                    session: name.to_string(),
                    reason: reason.clone(),
                });
            }
            drop(state);
            return Ok(existing.clone());
        }
    }
    create_session(host, name, lease_ctx).await
}

async fn create_session(
    host: &str,
    name: &str,
    lease_ctx: &ssh::LeaseContext,
) -> Result<Arc<SessionInner>, SessionError> {
    let conn = ssh::connect(host, lease_ctx).await?;
    let channel = conn
        .handle
        .channel_open_session()
        .await
        .map_err(SshError::from)?;
    channel
        .request_pty(
            true,
            "xterm-256color",
            80,
            24,
            0,
            0,
            &ssh::quiet_pty_modes(),
        )
        .await
        .map_err(SshError::from)?;
    channel.request_shell(true).await.map_err(SshError::from)?;

    let (read_half, write_half) = channel.split();
    let write_half = Arc::new(write_half);

    let state = AsyncMutex::new(SessionState {
        ring: RingBuffer::new(RING_CAPACITY),
        cursor: 0,
        busy: false,
        dead: None,
        last_activity: Instant::now(),
        run_seq: 0,
        current_run: None,
        last_result: None,
        spool_file: None,
        scrubber: FrameScrubber::default(),
        discard_until_ready: true,
    });
    let (wake_tx, _wake_rx) = watch::channel(0u64);

    let inner = Arc::new(SessionInner {
        host: host.to_string(),
        name: name.to_string(),
        write_half: write_half.clone(),
        state,
        wake_tx,
        _connection: conn,
    });

    let mut wake_rx = inner.wake_tx.subscribe();
    tokio::spawn(reader_loop(inner.clone(), read_half));

    // Quiesce the shell for scripted use (docs/internals/architecture.md), framed with its
    // own sentinel: everything the shell prints before that marker — login
    // banner, MOTD, prompt residue, the init line's own echo — is discarded
    // by the `discard_until_ready` gate, so none of it can ever be
    // attributed to the first user command.
    let init_sentinel = make_sentinel();
    let init_line = frame_command(INIT_COMMANDS, &init_sentinel);
    if let Err(e) = inner.write_half.data_bytes(init_line.into_bytes()).await {
        mark_dead(&inner, &format!("failed to initialize session shell: {e}")).await;
        return Err(SessionError::Dead {
            host: host.to_string(),
            session: name.to_string(),
            reason: format!("failed to initialize session shell: {e}"),
        });
    }

    // Wait for the init marker so the session starts clean. On timeout
    // (non-POSIX shell that never ran our printf?), proceed anyway with a
    // warning — the session is degraded (banner may leak into early output)
    // but not useless.
    let deadline = tokio::time::Instant::now() + SESSION_READY_TIMEOUT;
    loop {
        {
            let state = inner.state.lock().await;
            if let Some(reason) = &state.dead {
                return Err(SessionError::Dead {
                    host: host.to_string(),
                    session: name.to_string(),
                    reason: reason.clone(),
                });
            }
            if !state.discard_until_ready {
                break;
            }
        }
        tokio::select! {
            _ = wake_rx.changed() => {}
            _ = sleep_until(deadline) => {
                warn!(
                    host,
                    session = name,
                    "shell init marker never arrived; proceeding without banner consumption \
                     (login banner may appear in early session output)"
                );
                inner.state.lock().await.discard_until_ready = false;
                break;
            }
        }
    }

    {
        let mut reg = registry().lock().await;
        match reg.entry((host.to_string(), name.to_string())) {
            Entry::Occupied(existing) => {
                // Lost a concurrent-create race for the same key: keep the
                // established session, close ours.
                let existing = existing.get().clone();
                drop(reg);
                let _ = inner.write_half.close().await;
                return Ok(existing);
            }
            Entry::Vacant(slot) => {
                slot.insert(inner.clone());
            }
        }
    }

    audit::record(
        "session_opened",
        serde_json::json!({"host": host, "session": name}),
    );
    Ok(inner)
}

/// Background task: the sole owner of a session's `ChannelReadHalf`. Feeds
/// every byte into the ring buffer (and, while a `run` is in flight, the
/// active spool file), watches for the current run's sentinel, and detects
/// session death.
async fn reader_loop(inner: Arc<SessionInner>, mut read_half: ssh::ChannelReadHalf) {
    loop {
        match read_half.wait().await {
            Some(ssh::SessionChannelMsg::Data { data }) => on_data(&inner, &data).await,
            Some(ssh::SessionChannelMsg::ExtendedData { data, .. }) => on_data(&inner, &data).await,
            Some(ssh::SessionChannelMsg::Eof) | Some(ssh::SessionChannelMsg::Close) => {
                mark_dead(&inner, "remote closed the session channel").await;
                break;
            }
            None => {
                mark_dead(&inner, "SSH connection was lost").await;
                break;
            }
            _ => {}
        }
    }
}

async fn on_data(inner: &Arc<SessionInner>, data: &[u8]) {
    let mut state = inner.state.lock().await;
    ingest(&mut state, data);
    drop(state);
    inner.wake_tx.send_modify(|v| *v = v.wrapping_add(1));
}

/// Core of the reader path, factored out of `on_data` so it's directly
/// unit-testable without an SSH connection: scrub the raw PTY bytes, commit
/// payload to the ring/spool (unless still inside the init discard gate),
/// and settle runs when their markers arrive. Events are processed in
/// stream order so `end_offset` snapshots exclude any payload that arrived
/// after a marker within the same chunk.
fn ingest(state: &mut SessionState, data: &[u8]) {
    state.last_activity = Instant::now();
    for event in state.scrubber.feed(data) {
        match event {
            ScrubEvent::Payload(bytes) => {
                if state.discard_until_ready {
                    // Login banner / MOTD / prompt residue / init echo —
                    // consumed during open, never agent-visible (D2).
                    continue;
                }
                state.ring.push_slice(&bytes);
                if let Some(writer) = state.spool_file.as_mut() {
                    // The ledger avoids repeated tree scans; the actual
                    // append remains synchronous and failures detach only
                    // this spool while command/ring processing continues.
                    let path = writer.path.clone();
                    if let Err(error) = writer.write_payload(&bytes) {
                        warn!(
                            spool_path = %path.display(),
                            %error,
                            "spool write failed; command and in-memory output continue"
                        );
                        state.spool_file = None;
                    }
                }
            }
            ScrubEvent::Marker {
                sentinel,
                exit_code,
            } => handle_marker(state, &sentinel, exit_code),
        }
    }
}

/// A complete marker arrived (already scrubbed from payload). Decide what
/// it settles: the init gate, the current run (normally via its own
/// sentinel, or as `interrupted` via the armed resync probe sentinel), or
/// nothing (a stale probe from a run that already finished — swallowed).
fn handle_marker(state: &mut SessionState, sentinel: &str, exit_code: i32) {
    if state.discard_until_ready {
        // The shell-init frame completed; the session is now clean.
        state.discard_until_ready = false;
        return;
    }
    let Some(current) = &state.current_run else {
        // Stale marker (e.g. a resync probe whose run was already settled
        // by its own sentinel) — scrubbed from output, nothing to settle.
        return;
    };
    let outcome = if sentinel == current.sentinel {
        RunOutcome {
            exit_code: Some(exit_code),
            interrupted: false,
            end_offset: state.ring.total_written,
        }
    } else if current.resync.as_deref() == Some(sentinel) {
        // The command line was aborted by Ctrl-C before its own marker
        // could print; the resync probe settles the run as interrupted.
        RunOutcome {
            exit_code: None,
            interrupted: true,
            end_offset: state.ring.total_written,
        }
    } else {
        return; // unknown/stale marker — swallow
    };
    state.last_result = Some(outcome);
    state.busy = false;
    state.current_run = None;
    state.spool_file = None; // dropped => flushed and closed
}

async fn mark_dead(inner: &Arc<SessionInner>, reason: &str) {
    let mut state = inner.state.lock().await;
    if state.dead.is_none() {
        warn!(host = %inner.host, session = %inner.name, reason, "session died");
        state.dead = Some(reason.to_string());
        audit::record(
            "session_dead",
            serde_json::json!({"host": inner.host, "session": inner.name, "reason": reason}),
        );
    }
    state.busy = false;
    state.current_run = None;
    state.spool_file = None; // dropped => flushed and closed
    drop(state);
    inner.wake_tx.send_modify(|v| *v = v.wrapping_add(1));
}

fn dead_reply_output(state: &SessionState, start_offset: u64, raw: bool) -> (String, bool, u64) {
    let (bytes, _dropped) = state.ring.since(start_offset);
    shape_output(&bytes, raw)
}

// ---------------------------------------------------------------------------
// Public operations (backing the CLI command set, docs/internals/architecture.md)
// ---------------------------------------------------------------------------

use crate::proto::{PeekReply, RunReply};

/// `run <host> <command>` — docs/internals/architecture.md.
pub async fn run(
    host: &str,
    command: &str,
    session: Option<String>,
    timeout_secs: u64,
    raw: bool,
    lease_ctx: ssh::LeaseContext,
) -> Result<RunReply, SessionError> {
    let name = default_session_name(session);
    let inner = get_or_create_session(host, &name, &lease_ctx).await?;
    let mut wake_rx = inner.wake_tx.subscribe();

    let sentinel = make_sentinel();
    let start_offset;
    let spool_path;
    {
        let mut state = inner.state.lock().await;
        if let Some(reason) = state.dead.clone() {
            return Ok(dead_run_reply(host, &name, &state, 0, reason, raw));
        }
        if state.busy {
            return Err(SessionError::Busy {
                host: host.to_string(),
                session: name,
            });
        }
        state.run_seq += 1;
        start_offset = state.ring.total_written;
        let (path, file) = open_spool_file(host, &name, state.run_seq)?;
        spool_path = path;
        state.spool_file = Some(file);
        state.busy = true;
        state.current_run = Some(CurrentRun {
            sentinel: sentinel.clone(),
            resync: None,
        });
        state.last_result = None;
    }

    let cmd_line = frame_command(command, &sentinel);
    if let Err(e) = inner
        .write_half
        .data_bytes(cmd_line.clone().into_bytes())
        .await
    {
        mark_dead(&inner, &format!("failed to write to session: {e}")).await;
        let state = inner.state.lock().await;
        let reason = state.dead.clone().unwrap_or_default();
        return Ok(dead_run_reply(
            host,
            &name,
            &state,
            start_offset,
            reason,
            raw,
        ));
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs.max(1));
    loop {
        let still_busy = inner.state.lock().await.busy;
        if !still_busy {
            break;
        }
        tokio::select! {
            _ = wake_rx.changed() => continue,
            _ = sleep_until(deadline) => break,
        }
    }

    let mut state = inner.state.lock().await;
    if state.busy {
        // Timed out — command keeps running, we just stop waiting for it.
        let (output, truncated, total_bytes) = dead_reply_output(&state, start_offset, raw);
        return Ok(RunReply {
            host: host.to_string(),
            session: name,
            state: "running".to_string(),
            exit_code: None,
            output,
            truncated,
            total_bytes,
            spool_path: spool_path.display().to_string(),
            dead_reason: None,
        });
    }

    if let Some(reason) = state.dead.clone() {
        return Ok(dead_run_reply(
            host,
            &name,
            &state,
            start_offset,
            reason,
            raw,
        ));
    }

    let outcome = state
        .last_result
        .take()
        .expect("busy cleared without dying implies a marker was found and recorded a result");
    let (all_since_start, _dropped) = state.ring.since(start_offset);
    let want_len = ((outcome.end_offset - start_offset) as usize).min(all_since_start.len());
    let command_output = &all_since_start[..want_len];
    // Defensive only — echo is normally killed at the PTY/stty/readline
    // level; see `strip_echoed_command`. Match either the framed line we
    // actually wrote or the bare command.
    let command_output = strip_echoed_command(command_output, &[cmd_line.as_str(), command]);
    let (output, truncated, total_bytes) = shape_output(&command_output, raw);

    Ok(RunReply {
        host: host.to_string(),
        session: name,
        state: if outcome.interrupted {
            "interrupted".to_string()
        } else {
            "done".to_string()
        },
        exit_code: outcome.exit_code,
        output,
        truncated,
        total_bytes,
        spool_path: spool_path.display().to_string(),
        dead_reason: None,
    })
}

fn dead_run_reply(
    host: &str,
    name: &str,
    state: &SessionState,
    start_offset: u64,
    reason: String,
    raw: bool,
) -> RunReply {
    let (output, truncated, total_bytes) = dead_reply_output(state, start_offset, raw);
    RunReply {
        host: host.to_string(),
        session: name.to_string(),
        state: "dead".to_string(),
        exit_code: None,
        output,
        truncated,
        total_bytes,
        spool_path: String::new(),
        dead_reason: Some(reason),
    }
}

/// `peek <host>` — docs/internals/architecture.md.
pub async fn peek(
    host: &str,
    session: Option<String>,
    tail: Option<usize>,
    raw: bool,
) -> Result<PeekReply, SessionError> {
    let name = default_session_name(session);
    let inner = get_existing_session(host, &name).await?;
    let mut state = inner.state.lock().await;
    let label = state_label(&state).to_string();
    let dead_reason = state.dead.clone();

    let bytes = if let Some(n) = tail {
        state.ring.tail(n)
    } else {
        let (bytes, _dropped) = state.ring.since(state.cursor);
        state.cursor = state.ring.total_written;
        bytes
    };
    let (output, truncated, total_bytes) = shape_output(&bytes, raw);

    Ok(PeekReply {
        host: host.to_string(),
        session: name,
        state: label,
        output,
        truncated,
        total_bytes,
        dead_reason,
    })
}

/// `send <host> <keys>` — docs/internals/architecture.md.
pub async fn send(
    host: &str,
    keys: &str,
    session: Option<String>,
    newline: bool,
) -> Result<(), SessionError> {
    let name = default_session_name(session);
    let inner = get_existing_session(host, &name).await?;
    {
        let state = inner.state.lock().await;
        if let Some(reason) = &state.dead {
            return Err(SessionError::Dead {
                host: host.to_string(),
                session: name,
                reason: reason.clone(),
            });
        }
    }
    let mut payload = keys.as_bytes().to_vec();
    if newline {
        payload.push(b'\n');
    }
    inner
        .write_half
        .data_bytes(payload)
        .await
        .map_err(SshError::from)?;
    Ok(())
}

/// `interrupt <host>` — sends Ctrl-C (0x03), docs/internals/architecture.md.
///
/// If a run is in flight, Ctrl-C usually aborts the *whole* framed command
/// line in the interactive shell — including the trailing marker `printf` —
/// so the run's own sentinel would never arrive and the session would stay
/// `busy` forever (D3). To resync, we follow the 0x03 with a standalone
/// probe line carrying a fresh sentinel, and arm the current run to accept
/// EITHER marker: the original (command survived/trapped SIGINT and
/// finished normally — the queued probe then reports late and is swallowed
/// as stale) or the probe's (command was killed — the run settles as
/// `interrupted`, exit code unknown). If neither ever arrives (shell truly
/// wedged, e.g. Ctrl-C swallowed by a full-screen program), the session
/// stays busy and the `Busy` error on the next `run` points at `sloosh
/// kill` as the recovery path.
pub async fn interrupt(host: &str, session: Option<String>) -> Result<(), SessionError> {
    let name = default_session_name(session);
    let inner = get_existing_session(host, &name).await?;
    let probe = {
        let mut state = inner.state.lock().await;
        if let Some(reason) = &state.dead {
            return Err(SessionError::Dead {
                host: host.to_string(),
                session: name,
                reason: reason.clone(),
            });
        }
        if state.busy {
            if let Some(current) = state.current_run.as_mut() {
                // Re-arming on repeat interrupts replaces the probe sentinel;
                // an older probe's marker (if its printf still runs) is
                // scrubbed and swallowed as stale by `handle_marker`.
                let resync_sentinel = make_sentinel();
                current.resync = Some(resync_sentinel.clone());
                Some(marker_printf(&resync_sentinel))
            } else {
                None
            }
        } else {
            None
        }
    };
    inner
        .write_half
        .data_bytes(vec![0x03u8])
        .await
        .map_err(SshError::from)?;
    if let Some(probe_line) = probe {
        inner
            .write_half
            .data_bytes(probe_line.into_bytes())
            .await
            .map_err(SshError::from)?;
    }
    Ok(())
}

/// `open <host> <name>` — explicit create-or-reuse of a named session
/// (docs/internals/architecture.md). Unlike `run`, never implicitly targets "default".
pub async fn open(
    host: &str,
    name: &str,
    lease_ctx: ssh::LeaseContext,
) -> Result<SessionSummary, SessionError> {
    let inner = get_or_create_session(host, name, &lease_ctx).await?;
    let state = inner.state.lock().await;
    Ok(summarize(host, name, &state))
}

/// `kill <host>` — docs/internals/architecture.md. Removes the session from the registry and
/// closes its channel; never reconnects (this is the only way back from a
/// `dead` session, or to end a healthy one).
pub async fn kill(host: &str, session: Option<String>) -> Result<(), SessionError> {
    let name = default_session_name(session);
    let inner = {
        let mut reg = registry().lock().await;
        reg.remove(&(host.to_string(), name.clone()))
    };
    let Some(inner) = inner else {
        return Err(SessionError::NotFound {
            host: host.to_string(),
            session: name,
        });
    };
    let _ = inner.write_half.close().await;
    Ok(())
}

/// `ls [--host]` — docs/internals/architecture.md.
pub async fn ls(host_filter: Option<String>) -> Vec<SessionSummary> {
    let reg = registry().lock().await;
    let mut out = Vec::with_capacity(reg.len());
    for ((host, name), inner) in reg.iter() {
        if let Some(hf) = &host_filter {
            if hf != host {
                continue;
            }
        }
        let state = inner.state.lock().await;
        out.push(summarize(host, name, &state));
    }
    drop(reg);
    out.sort_by(|a, b| (a.host.as_str(), a.name.as_str()).cmp(&(b.host.as_str(), b.name.as_str())));
    out
}

/// Summaries of all live sessions, for `status`.
pub async fn list_summaries() -> Vec<SessionSummary> {
    ls(None).await
}

// ---------------------------------------------------------------------------
// `put`/`get` over SFTP (docs/internals/architecture.md)
// ---------------------------------------------------------------------------

fn sftp_client_config() -> SftpConfig {
    SftpConfig {
        request_timeout_secs: SFTP_REQUEST_TIMEOUT_SECS,
        ..SftpConfig::default()
    }
}

/// Get (or create) the named session, then open a fresh SFTP-subsystem
/// channel on its *existing* SSH connection (docs/internals/architecture.md: "put/get 走既有
/// 连接的 SFTP channel" — reuse the authenticated connection, never redial or
/// reauthenticate per transfer). Returns the resolved session name alongside
/// the SFTP handle so callers can echo it back in their reply.
async fn sftp_session(
    host: &str,
    session: Option<String>,
    lease_ctx: ssh::LeaseContext,
) -> Result<(String, SftpSession), SessionError> {
    let name = default_session_name(session);
    let inner = get_or_create_session(host, &name, &lease_ctx).await?;
    let channel = inner
        ._connection
        .handle
        .channel_open_session()
        .await
        .map_err(SshError::from)?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(SshError::from)?;
    let sftp = SftpSession::new_with_config(channel.into_stream(), sftp_client_config())
        .await
        .map_err(|e| SessionError::Sftp {
            host: host.to_string(),
            reason: e.to_string(),
        })?;
    Ok((name, sftp))
}

/// Translate an SFTP protocol error on `path` into a self-teaching
/// `SessionError` — `NoSuchFile`/`PermissionDenied` get a specific message
/// (docs/internals/architecture.md); anything else falls back to the generic SFTP error.
fn remote_path_error(host: &str, path: &str, err: SftpClientError) -> SessionError {
    if let SftpClientError::Status(status) = &err {
        let reason = match status.status_code {
            StatusCode::NoSuchFile => Some("no such file or directory"),
            StatusCode::PermissionDenied => Some("permission denied"),
            _ => None,
        };
        if let Some(reason) = reason {
            return SessionError::RemotePath {
                host: host.to_string(),
                path: path.to_string(),
                reason: reason.to_string(),
            };
        }
    }
    SessionError::Sftp {
        host: host.to_string(),
        reason: err.to_string(),
    }
}

/// Open the remote half of an upload. The caller streams bounded chunks from
/// the sandboxed CLI into [`UploadTransfer::write_chunk`]; no local path is
/// ever opened by the daemon and total file size is unbounded.
pub async fn begin_put(
    host: &str,
    session: Option<String>,
    local_path: &str,
    remote_path: &str,
    lease_ctx: ssh::LeaseContext,
) -> Result<UploadTransfer, SessionError> {
    let (session_name, sftp) = sftp_session(host, session, lease_ctx).await?;
    let remote_file = sftp
        .open_with_flags(
            remote_path,
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
        )
        .await
        .map_err(|e| remote_path_error(host, remote_path, e))?;
    Ok(UploadTransfer {
        host: host.to_string(),
        session: session_name,
        local_path: local_path.to_string(),
        remote_path: remote_path.to_string(),
        remote_file,
        bytes_transferred: 0,
    })
}

pub struct UploadTransfer {
    host: String,
    session: String,
    local_path: String,
    remote_path: String,
    remote_file: SftpFile,
    bytes_transferred: u64,
}

impl UploadTransfer {
    pub async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), SessionError> {
        self.remote_file
            .write_all(chunk)
            .await
            .map_err(|source| SessionError::Transfer {
                host: self.host.clone(),
                local: self.local_path.clone(),
                remote: self.remote_path.clone(),
                source,
            })?;
        self.bytes_transferred = self.bytes_transferred.saturating_add(chunk.len() as u64);
        Ok(())
    }

    pub async fn finish(mut self) -> Result<TransferReply, SessionError> {
        self.remote_file
            .shutdown()
            .await
            .map_err(|source| SessionError::Transfer {
                host: self.host.clone(),
                local: self.local_path.clone(),
                remote: self.remote_path.clone(),
                source,
            })?;
        audit::record(
            "put",
            serde_json::json!({
                "host": self.host,
                "session": self.session,
                "local_path": self.local_path,
                "remote_path": self.remote_path,
                "bytes": self.bytes_transferred,
            }),
        );
        Ok(TransferReply {
            host: self.host,
            session: self.session,
            local_path: self.local_path,
            remote_path: self.remote_path,
            bytes_transferred: self.bytes_transferred,
        })
    }
}

/// Open the remote half of a download. The caller repeatedly invokes
/// [`DownloadTransfer::read_chunk`] and forwards each bounded chunk to the
/// sandboxed CLI, which owns the local destination file.
pub async fn begin_get(
    host: &str,
    session: Option<String>,
    remote_path: &str,
    local_path: &str,
    lease_ctx: ssh::LeaseContext,
) -> Result<DownloadTransfer, SessionError> {
    let (session_name, sftp) = sftp_session(host, session, lease_ctx).await?;
    let remote_file = sftp
        .open(remote_path)
        .await
        .map_err(|e| remote_path_error(host, remote_path, e))?;
    Ok(DownloadTransfer {
        host: host.to_string(),
        session: session_name,
        local_path: local_path.to_string(),
        remote_path: remote_path.to_string(),
        remote_file,
        bytes_transferred: 0,
    })
}

pub struct DownloadTransfer {
    host: String,
    session: String,
    local_path: String,
    remote_path: String,
    remote_file: SftpFile,
    bytes_transferred: u64,
}

impl DownloadTransfer {
    pub async fn read_chunk(&mut self, buffer: &mut [u8]) -> Result<usize, SessionError> {
        let read =
            self.remote_file
                .read(buffer)
                .await
                .map_err(|source| SessionError::Transfer {
                    host: self.host.clone(),
                    local: self.local_path.clone(),
                    remote: self.remote_path.clone(),
                    source,
                })?;
        self.bytes_transferred = self.bytes_transferred.saturating_add(read as u64);
        Ok(read)
    }

    pub fn finish(self) -> TransferReply {
        audit::record(
            "get",
            serde_json::json!({
                "host": self.host,
                "session": self.session,
                "local_path": self.local_path,
                "remote_path": self.remote_path,
                "bytes": self.bytes_transferred,
            }),
        );
        TransferReply {
            host: self.host,
            session: self.session,
            local_path: self.local_path,
            remote_path: self.remote_path,
            bytes_transferred: self.bytes_transferred,
        }
    }
}

/// Spawn the background idle-session reaper. Call once, at daemon startup.
pub fn spawn_idle_reaper() {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(IDLE_REAP_SWEEP_INTERVAL).await;
            reap_idle_sessions().await;
        }
    });
}

async fn reap_idle_sessions() {
    let victims: Vec<SessionKey> = {
        let reg = registry().lock().await;
        let mut victims = Vec::new();
        for (key, inner) in reg.iter() {
            let state = inner.state.lock().await;
            if state.dead.is_none() && state.last_activity.elapsed() >= IDLE_REAP_AFTER {
                victims.push(key.clone());
            }
        }
        victims
    };
    for (host, name) in victims {
        info!(
            host,
            session = name,
            "reaping idle session (no activity for 8h)"
        );
        let _ = kill(&host, Some(name)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- ring buffer -------------------------------------------------

    #[test]
    fn ring_buffer_evicts_oldest_beyond_capacity() {
        let mut ring = RingBuffer::new(4);
        ring.push_slice(b"abcdef"); // "cdef" survives (last 4)
        assert_eq!(ring.tail(10), b"cdef");
        assert_eq!(ring.total_written, 6);
    }

    #[test]
    fn ring_buffer_since_cursor_incremental() {
        let mut ring = RingBuffer::new(1024);
        ring.push_slice(b"hello ");
        let cursor = ring.total_written;
        ring.push_slice(b"world");
        let (bytes, dropped) = ring.since(cursor);
        assert_eq!(bytes, b"world");
        assert!(!dropped);
    }

    #[test]
    fn ring_buffer_since_reports_dropped_when_evicted() {
        let mut ring = RingBuffer::new(4);
        ring.push_slice(b"ab");
        let cursor = ring.total_written; // points right after "ab"
        ring.push_slice(b"cdefgh"); // evicts "ab" and more
        let (_, dropped) = ring.since(cursor);
        assert!(dropped);
    }

    #[test]
    fn ring_buffer_tail_n() {
        let mut ring = RingBuffer::new(1024);
        ring.push_slice(b"0123456789");
        assert_eq!(ring.tail(3), b"789");
        assert_eq!(ring.tail(100), b"0123456789");
    }

    // --- sentinel framing / scrubber ----------------------------------

    /// Collect a scrubber event stream into (concatenated payload, markers).
    fn drain(events: Vec<ScrubEvent>) -> (Vec<u8>, Vec<(String, i32)>) {
        let mut payload = Vec::new();
        let mut markers = Vec::new();
        for event in events {
            match event {
                ScrubEvent::Payload(bytes) => payload.extend_from_slice(&bytes),
                ScrubEvent::Marker {
                    sentinel,
                    exit_code,
                } => markers.push((sentinel, exit_code)),
            }
        }
        (payload, markers)
    }

    #[test]
    fn scrubber_extracts_marker_and_clean_payload() {
        let s = make_sentinel();
        let stream = format!("hello world\r\n\r\n{s}0{s}\r\n");
        let mut sc = FrameScrubber::default();
        let (payload, markers) = drain(sc.feed(stream.as_bytes()));
        assert_eq!(payload, b"hello world\r\n");
        assert_eq!(markers, vec![(s, 0)]);
    }

    #[test]
    fn scrubber_nonzero_exit_code() {
        let s = make_sentinel();
        let stream = format!("oops\r\n\r\n{s}127{s}\r\n");
        let mut sc = FrameScrubber::default();
        let (_, markers) = drain(sc.feed(stream.as_bytes()));
        assert_eq!(markers[0].1, 127);
    }

    #[test]
    fn scrubber_result_is_invariant_across_all_chunk_splits() {
        // The D1 invariant, exercised against every possible split point
        // (including splits inside the sentinel and inside the separator
        // newlines): payload and markers must come out identical, and no
        // sentinel byte sequence may ever appear in the payload.
        let s = make_sentinel();
        let stream = format!("line one\r\nline two\r\n\r\n{s}42{s}\r\nafter");
        let bytes = stream.as_bytes();

        let mut reference = FrameScrubber::default();
        let (ref_payload, ref_markers) = drain(reference.feed(bytes));
        assert_eq!(ref_payload, b"line one\r\nline two\r\nafter");
        assert_eq!(ref_markers, vec![(s.clone(), 42)]);
        assert!(
            !String::from_utf8_lossy(&ref_payload).contains("__sloosh_"),
            "sentinel leaked into payload"
        );

        for split in 0..=bytes.len() {
            let mut sc = FrameScrubber::default();
            let mut events = sc.feed(&bytes[..split]);
            events.extend(sc.feed(&bytes[split..]));
            let (payload, markers) = drain(events);
            assert_eq!(payload, ref_payload, "split at {split} changed payload");
            assert_eq!(markers, ref_markers, "split at {split} changed markers");
        }

        // Byte-at-a-time, the worst case.
        let mut sc = FrameScrubber::default();
        let mut events = Vec::new();
        for b in bytes {
            events.extend(sc.feed(std::slice::from_ref(b)));
        }
        let (payload, markers) = drain(events);
        assert_eq!(payload, ref_payload);
        assert_eq!(markers, ref_markers);
    }

    #[test]
    fn scrubber_releases_lone_sentinel_and_echo_lookalikes_as_payload() {
        // A lone sentinel (no digits+twin), or an echoed framed command
        // (`%s` between the sentinels), is not a marker: pattern scan must
        // release it as payload rather than hold it forever.
        let s = make_sentinel();
        let mut sc = FrameScrubber::default();
        let stream = format!("{s}%s{s} not a marker\r\nnext");
        let (payload, markers) = drain(sc.feed(stream.as_bytes()));
        assert_eq!(payload, stream.as_bytes());
        assert!(markers.is_empty());

        // Sentinel-ish text with non-hex characters is plain payload too.
        // (A chunk-final "\r\n" is briefly held back as a potential marker
        // separator — the trailing "x" here resolves it as payload.)
        let mut sc = FrameScrubber::default();
        let (payload, markers) = drain(sc.feed(b"__sloosh_zzz not hex\r\nx"));
        assert_eq!(payload, b"__sloosh_zzz not hex\r\nx");
        assert!(markers.is_empty());
    }

    #[test]
    fn scrubber_holds_partial_marker_until_it_resolves() {
        let s = make_sentinel();
        let mut sc = FrameScrubber::default();
        // Feed output plus the separator and half the marker.
        let head = format!("out\r\n\r\n{}", &s[..20]);
        let (payload, markers) = drain(sc.feed(head.as_bytes()));
        assert_eq!(payload, b"out\r\n", "separator + partial marker held back");
        assert!(markers.is_empty());
        // Now the rest of the marker.
        let tail = format!("{}0{s}\r\n", &s[20..]);
        let (payload, markers) = drain(sc.feed(tail.as_bytes()));
        assert!(payload.is_empty());
        assert_eq!(markers, vec![(s, 0)]);
    }

    #[test]
    fn scrubber_eats_trailing_newline_after_marker_across_splits() {
        let s = make_sentinel();
        let mut sc = FrameScrubber::default();
        let (_, markers) = drain(sc.feed(format!("{s}0{s}").as_bytes()));
        assert_eq!(markers.len(), 1);
        // The printf's trailing newline arrives split across two feeds.
        assert!(drain(sc.feed(b"\r")).0.is_empty());
        assert!(drain(sc.feed(b"\n")).0.is_empty());
        let (payload, _) = drain(sc.feed(b"next"));
        assert_eq!(payload, b"next");
    }

    // --- ingest / marker handling (D2, D3) -----------------------------

    fn test_state() -> SessionState {
        SessionState {
            ring: RingBuffer::new(RING_CAPACITY),
            cursor: 0,
            busy: false,
            dead: None,
            last_activity: Instant::now(),
            run_seq: 0,
            current_run: None,
            last_result: None,
            spool_file: None,
            scrubber: FrameScrubber::default(),
            discard_until_ready: false,
        }
    }

    fn ring_contents(state: &SessionState) -> Vec<u8> {
        state.ring.tail(usize::MAX)
    }

    #[test]
    fn banner_and_init_echo_are_discarded_until_init_marker() {
        // D2: everything before the shell-init frame's marker — banner,
        // MOTD, prompt residue, the init line's own echo (which contains
        // sentinel-lookalike text) — is consumed during open.
        let init_sentinel = make_sentinel();
        let mut state = test_state();
        state.discard_until_ready = true;

        let echoed_init = frame_command(INIT_COMMANDS, &init_sentinel);
        let stream = format!(
            "Welcome to Ubuntu 24.04 LTS\r\n* Docs: https://example\r\nroot@vm:~# {}\r\n\r\n{init_sentinel}0{init_sentinel}\r\n",
            echoed_init.trim_end()
        );
        ingest(&mut state, stream.as_bytes());

        assert!(!state.discard_until_ready, "init marker clears the gate");
        assert!(
            ring_contents(&state).is_empty(),
            "banner/prompt/init echo must never reach the ring, got {:?}",
            String::from_utf8_lossy(&ring_contents(&state))
        );

        // The first real output after the gate is committed normally. (The
        // chunk-final "\r\n" is briefly held back as a potential marker
        // separator; the next chunk resolves it as payload.)
        ingest(&mut state, b"real output\r\n");
        ingest(&mut state, b"more\r\nx");
        assert_eq!(ring_contents(&state), b"real output\r\nmore\r\nx");
    }

    #[test]
    fn resync_probe_marker_settles_interrupted_run() {
        // D3, race A: Ctrl-C killed the command line, so only the resync
        // probe's marker ever arrives — the run settles as interrupted
        // instead of wedging the session in busy forever.
        let s1 = make_sentinel();
        let rs = make_sentinel();
        let mut state = test_state();
        state.busy = true;
        state.current_run = Some(CurrentRun {
            sentinel: s1,
            resync: Some(rs.clone()),
        });

        ingest(
            &mut state,
            format!("partial output\r\n\r\n{rs}130{rs}\r\n").as_bytes(),
        );

        assert!(!state.busy, "resync marker must clear busy");
        assert!(state.current_run.is_none());
        let outcome = state.last_result.as_ref().expect("run settled");
        assert!(outcome.interrupted);
        assert_eq!(outcome.exit_code, None, "exit code unknowable after ^C");
        assert_eq!(ring_contents(&state), b"partial output\r\n");
    }

    #[test]
    fn original_marker_wins_when_command_survives_interrupt() {
        // D3, race B: the command survived/trapped SIGINT and finished
        // normally — its own marker arrives first and settles the run with
        // a real exit code; the queued probe's marker arrives later and is
        // swallowed as stale (and scrubbed from output).
        let s1 = make_sentinel();
        let rs = make_sentinel();
        let mut state = test_state();
        state.busy = true;
        state.current_run = Some(CurrentRun {
            sentinel: s1.clone(),
            resync: Some(rs.clone()),
        });

        ingest(
            &mut state,
            format!("done\r\n\r\n{s1}0{s1}\r\n\r\n{rs}0{rs}\r\n").as_bytes(),
        );

        assert!(!state.busy);
        let outcome = state.last_result.as_ref().expect("run settled");
        assert!(!outcome.interrupted);
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(
            ring_contents(&state),
            b"done\r\n",
            "neither marker may leak into the ring"
        );
    }

    #[test]
    fn stale_probe_marker_between_runs_is_swallowed() {
        let rs = make_sentinel();
        let mut state = test_state();
        ingest(&mut state, format!("{rs}0{rs}\r\n").as_bytes());
        assert!(state.last_result.is_none());
        assert!(ring_contents(&state).is_empty());
        assert!(!state.busy);
    }

    #[test]
    fn end_offset_excludes_payload_arriving_after_marker_in_same_chunk() {
        let s1 = make_sentinel();
        let mut state = test_state();
        state.busy = true;
        state.current_run = Some(CurrentRun {
            sentinel: s1.clone(),
            resync: None,
        });

        ingest(
            &mut state,
            format!("out\r\n\r\n{s1}0{s1}\r\ntrailing").as_bytes(),
        );

        let outcome = state.last_result.as_ref().expect("run settled");
        assert_eq!(outcome.end_offset, b"out\r\n".len() as u64);
        assert_eq!(ring_contents(&state), b"out\r\ntrailing");
    }

    // --- ANSI stripping -------------------------------------------------

    #[test]
    fn strip_ansi_removes_csi_color_codes() {
        let input = b"\x1b[31mred\x1b[0m plain";
        assert_eq!(strip_ansi(input), b"red plain");
    }

    #[test]
    fn strip_ansi_removes_osc_sequences() {
        let mut input = Vec::new();
        input.extend_from_slice(b"\x1b]0;window title\x07visible");
        assert_eq!(strip_ansi(&input), b"visible");
    }

    #[test]
    fn strip_ansi_removes_osc_terminated_by_st() {
        let mut input = Vec::new();
        input.extend_from_slice(b"\x1b]0;title\x1b\\visible");
        assert_eq!(strip_ansi(&input), b"visible");
    }

    #[test]
    fn strip_ansi_passes_through_plain_text() {
        assert_eq!(strip_ansi(b"no escapes here"), b"no escapes here");
    }

    #[test]
    fn strip_ansi_handles_trailing_incomplete_escape() {
        // Truncated ESC at end of buffer shouldn't panic or hang.
        assert_eq!(strip_ansi(b"abc\x1b"), b"abc");
    }

    // --- echo suppression heuristic -------------------------------------

    #[test]
    fn strip_echoed_command_removes_matching_first_line() {
        let out = b"ls -la\ntotal 0\n-rw-r--r-- 1 u u 0 file\n";
        let stripped = strip_echoed_command(out, &["ls -la"]);
        assert_eq!(stripped, b"total 0\n-rw-r--r-- 1 u u 0 file\n");
    }

    #[test]
    fn strip_echoed_command_matches_framed_line_with_cr() {
        // The echoed line is the *framed* command (with the sentinel
        // printf), CR-terminated by PTY newline translation.
        let s = make_sentinel();
        let framed = frame_command("echo hi", &s);
        let out = format!("{}\r\nhi\r\n", framed.trim_end());
        let stripped = strip_echoed_command(out.as_bytes(), &[framed.as_str(), "echo hi"]);
        assert_eq!(stripped, b"hi\r\n");
    }

    #[test]
    fn strip_echoed_command_leaves_output_alone_when_not_echoed() {
        let out = b"total 0\nfile\n";
        let stripped = strip_echoed_command(out, &["ls -la"]);
        assert_eq!(stripped, out);
    }

    // --- truncation -------------------------------------------------

    #[test]
    fn shape_output_no_truncation_under_cap() {
        let (text, truncated, total) = shape_output(b"short output", false);
        assert_eq!(text, "short output");
        assert!(!truncated);
        assert_eq!(total, 12);
    }

    #[test]
    fn shape_output_truncates_and_marks_over_cap() {
        let big = "x".repeat(MAX_OUTPUT_CHARS + 500);
        let (text, truncated, total) = shape_output(big.as_bytes(), false);
        assert!(truncated);
        assert_eq!(total, big.len() as u64);
        assert!(text.contains("truncated"));
        assert!(text.ends_with(&"x".repeat(100)));
    }

    #[test]
    fn shape_output_raw_mode_skips_ansi_stripping() {
        let input = b"\x1b[31mred\x1b[0m";
        let (text, _, _) = shape_output(input, true);
        assert!(text.contains("\x1b[31m"));
        let (text2, _, _) = shape_output(input, false);
        assert!(!text2.contains("\x1b[31m"));
    }

    // --- frame_command / make_sentinel ------------------------------

    #[test]
    fn frame_command_wraps_with_sentinel_and_exit_code_probe() {
        let framed = frame_command("echo hi", "MYSENT");
        assert!(framed.starts_with("echo hi; printf"));
        assert!(framed.contains("MYSENT%sMYSENT"));
        assert!(framed.ends_with("$?\n"));
    }

    #[test]
    fn make_sentinel_is_unique_and_shell_safe() {
        let a = make_sentinel();
        let b = make_sentinel();
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    }

    // --- spool safety / cleanup ----------------------------------------

    fn temp_spool_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sloosh-spool-{label}-{}-{}",
            std::process::id(),
            make_sentinel()
        ))
    }

    #[test]
    fn spool_paths_encode_untrusted_host_and_session_names() {
        let sandbox = temp_spool_root("traversal");
        let root = sandbox.join("spool");
        let escaped = sandbox.join("escaped");
        let (path, writer) =
            open_spool_file_under(&root, "../../escaped/host", "../session/../../outside", 1)
                .unwrap();
        drop(writer);

        assert!(path.starts_with(&root));
        let relative = path.strip_prefix(&root).unwrap();
        assert_eq!(relative.components().count(), 2);
        assert!(
            !escaped.exists(),
            "untrusted names must not escape spool root"
        );
        let session_component = relative.components().next().unwrap().as_os_str();
        let session_component = session_component.to_string_lossy();
        assert!(!session_component.contains('/'));
        assert!(!session_component.contains(".."));

        let long = "../".repeat(500);
        let encoded = encode_spool_name(&long);
        assert!(encoded.len() <= MAX_ENCODED_SPOOL_NAME_BYTES);
        assert!(!encoded.contains('/'));
        let _ = std::fs::remove_dir_all(&sandbox);
    }

    #[test]
    fn spool_directories_and_files_are_private() {
        let root = temp_spool_root("permissions");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();

        let (path, writer) = open_spool_file_under(&root, "host", "session", 1).unwrap();
        drop(writer);

        let root_mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(root_mode, 0o700);
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reused_run_sequence_never_truncates_retained_history() {
        let root = temp_spool_root("sequence-collision");
        ensure_private_dir(&root).unwrap();
        let dir = spool_dir_under(&root, "host", "session");
        ensure_private_dir(&dir).unwrap();
        let history = dir.join("00000001.log");
        std::fs::write(&history, b"retained history").unwrap();

        let (new_path, writer) = open_spool_file_under(&root, "host", "session", 1).unwrap();

        assert_ne!(new_path, history, "a reused sequence needs a unique path");
        assert_eq!(std::fs::read(&history).unwrap(), b"retained history");
        drop(writer);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn incomplete_initial_scan_pauses_persistence_until_a_complete_retry() {
        let root = temp_spool_root("scan-retry");
        ensure_private_dir(&root).unwrap();
        let unreadable = root.join("unreadable");
        ensure_private_dir(&unreadable).unwrap();
        let history = unreadable.join("00000001.log");
        let history_file = std::fs::File::create(&history).unwrap();
        history_file.set_len(32).unwrap();
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();

        let mut ledger = SpoolLedger::new(root.clone(), 64);
        ledger.initialize();
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(!ledger.initialized);
        assert_eq!(ledger.claim_bytes(&root.join("active.log"), 16), 0);

        ledger.next_scan_attempt = None;
        ledger.initialize();
        assert!(ledger.initialized);
        assert_eq!(ledger.total_bytes, 32);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn spool_limit_does_not_stop_ring_or_command_completion() {
        let root = temp_spool_root("limit");
        ensure_private_dir(&root).unwrap();
        let path = root.join("limited.log");
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();

        let sentinel = make_sentinel();
        let mut state = test_state();
        state.busy = true;
        state.current_run = Some(CurrentRun {
            sentinel: sentinel.clone(),
            resync: None,
        });
        state.spool_file = Some(SpoolWriter::with_limit(file, path.clone(), 128));

        let payload = "x".repeat(256);
        ingest(
            &mut state,
            format!("{payload}\r\n\r\n{sentinel}0{sentinel}\r\n").as_bytes(),
        );

        assert!(!state.busy, "marker handling must continue after spool cap");
        assert_eq!(state.last_result.as_ref().unwrap().exit_code, Some(0));
        assert!(
            ring_contents(&state).len() > 128,
            "memory ring must keep output beyond disk cap"
        );
        let persisted = std::fs::read(&path).unwrap();
        assert_eq!(persisted.len(), 128);
        assert!(persisted.ends_with(SPOOL_LIMIT_MARKER));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cleanup_spool_dir_removes_oldest_when_over_budget() {
        let dir = temp_spool_root("cleanup");
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..3u32 {
            let path = dir.join(format!("{i:08}.log"));
            let file = std::fs::File::create(path).unwrap();
            file.set_len(32 * 1024 * 1024).unwrap();
        }
        let saved = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(saved, 3);
        cleanup_spool_dir_preserving(&dir, None);
        let remaining: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        let total: u64 = remaining
            .iter()
            .map(|entry| entry.metadata().unwrap().len())
            .sum();
        assert!(remaining.len() < 3);
        assert!(total <= MAX_SPOOL_DIR_BYTES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn global_spool_budget_removes_oldest_files_across_sessions() {
        let root = temp_spool_root("global-cleanup");
        ensure_private_dir(&root).unwrap();
        for i in 0..3u32 {
            let dir = root.join(format!("session-{i}"));
            ensure_private_dir(&dir).unwrap();
            let file = std::fs::File::create(dir.join("00000001.log")).unwrap();
            file.set_len(512 * 1024 * 1024).unwrap();
        }

        cleanup_spool_root(&root).unwrap();
        let total: u64 = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .flat_map(|dir| {
                std::fs::read_dir(dir.path())
                    .unwrap()
                    .filter_map(Result::ok)
            })
            .map(|file| file.metadata().unwrap().len())
            .sum();
        assert!(total <= MAX_SPOOL_ROOT_BYTES);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn more_than_sixteen_empty_spool_writers_can_run_concurrently() {
        let root = temp_spool_root("many-empty-writers");
        let mut writers = Vec::new();

        for i in 0..17 {
            let opened = open_spool_file_under(&root, "host", &format!("session-{i}"), 1);
            match opened {
                Ok((_, writer)) => writers.push(writer),
                Err(error) => {
                    panic!("empty run {i} must not consume a phantom 64 MiB reservation: {error}")
                }
            }
        }

        assert_eq!(writers.len(), 17);
        assert_eq!(
            lock_spool_ledger(&spool_ledger(&root)).scan_count,
            1,
            "root tree must be indexed once, not once per run"
        );
        drop(writers);
        assert_eq!(
            lock_spool_ledger(&spool_ledger(&root)).scan_count,
            1,
            "dropping writers must use the ledger, not rescan the root"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_active_writer_does_not_evict_retained_history() {
        let root = temp_spool_root("empty-writer-history");
        ensure_private_dir(&root).unwrap();
        let history_dir = root.join("history");
        ensure_private_dir(&history_dir).unwrap();
        let history = history_dir.join("00000001.log");
        let history_file = std::fs::File::create(&history).unwrap();
        history_file.set_len(970 * 1024 * 1024).unwrap();

        let (_, writer) = open_spool_file_under(&root, "host", "active", 1).unwrap();
        assert!(
            history.exists(),
            "zero-byte active writer must not evict real retained history"
        );

        drop(writer);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn global_spool_ledger_charges_actual_bytes_and_evicts_oldest_inactive() {
        let root = temp_spool_root("actual-byte-ledger");
        ensure_private_dir(&root).unwrap();
        let history_dir = root.join("history");
        ensure_private_dir(&history_dir).unwrap();
        let history = history_dir.join("00000001.log");
        let history_file = std::fs::File::create(&history).unwrap();
        history_file.set_len(80).unwrap();

        let active_dir = root.join("active");
        ensure_private_dir(&active_dir).unwrap();
        let active = active_dir.join("00000001.log");
        let active_file = std::fs::File::create(&active).unwrap();
        let ledger = Arc::new(Mutex::new(SpoolLedger::new(root.clone(), 128)));
        {
            let mut accounting = lock_spool_ledger(&ledger);
            accounting.initialize();
            accounting.register_active(&active);
            assert_eq!(accounting.total_bytes, 80);
        }
        let mut writer = SpoolWriter::with_accounting(active_file, active.clone(), 256, ledger);

        writer.write_payload(&[b'x'; 80]).unwrap();

        assert!(
            !history.exists(),
            "oldest inactive history should make room"
        );
        assert_eq!(std::fs::metadata(&active).unwrap().len(), 80);
        assert_eq!(
            lock_spool_ledger(writer.ledger.as_ref().unwrap()).total_bytes,
            80
        );
        drop(writer);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn global_spool_ledger_never_evicts_active_files() {
        let root = temp_spool_root("active-protection");
        ensure_private_dir(&root).unwrap();
        let dir = root.join("sessions");
        ensure_private_dir(&dir).unwrap();
        let first_path = dir.join("00000001.log");
        let second_path = dir.join("00000002.log");
        let first_file = std::fs::File::create(&first_path).unwrap();
        let second_file = std::fs::File::create(&second_path).unwrap();
        let ledger = Arc::new(Mutex::new(SpoolLedger::new(root.clone(), 100)));
        {
            let mut accounting = lock_spool_ledger(&ledger);
            accounting.initialize();
            accounting.register_active(&first_path);
            accounting.register_active(&second_path);
        }
        let mut first =
            SpoolWriter::with_accounting(first_file, first_path.clone(), 256, ledger.clone());
        let mut second =
            SpoolWriter::with_accounting(second_file, second_path.clone(), 256, ledger.clone());

        first.write_payload(&[b'a'; 80]).unwrap();
        second.write_payload(&[b'b'; 80]).unwrap();

        assert!(first_path.exists());
        assert!(second_path.exists());
        assert_eq!(std::fs::metadata(&first_path).unwrap().len(), 80);
        assert_eq!(std::fs::metadata(&second_path).unwrap().len(), 20);
        assert_eq!(lock_spool_ledger(&ledger).total_bytes, 100);
        drop(first);
        drop(second);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cleanup_delete_failure_does_not_block_new_spool_writer() {
        let root = temp_spool_root("cleanup-failure");
        ensure_private_dir(&root).unwrap();
        let history_dir = root.join("read-only-history");
        ensure_private_dir(&history_dir).unwrap();
        let history = history_dir.join("00000001.log");
        let history_file = std::fs::File::create(&history).unwrap();
        history_file
            .set_len(MAX_SPOOL_ROOT_BYTES + MAX_SPOOL_FILE_BYTES)
            .unwrap();
        std::fs::set_permissions(&history_dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let opened = open_spool_file_under(&root, "host", "new-run", 1);

        std::fs::set_permissions(&history_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (_, writer) = opened.expect("retention cleanup failure must not fail a remote run");
        cleanup_spool_root(&root).unwrap();
        assert!(
            !history.exists(),
            "a later cleanup pass must retry transient deletion failures"
        );
        drop(writer);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cleanup_failure_stops_persistence_but_not_ring_or_command() {
        let root = temp_spool_root("cleanup-failure-ingest");
        ensure_private_dir(&root).unwrap();
        let history_dir = root.join("read-only-history");
        ensure_private_dir(&history_dir).unwrap();
        let history = history_dir.join("00000001.log");
        let history_file = std::fs::File::create(&history).unwrap();
        history_file.set_len(128).unwrap();
        std::fs::set_permissions(&history_dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let ledger = Arc::new(Mutex::new(SpoolLedger::new(root.clone(), 64)));
        {
            let mut accounting = lock_spool_ledger(&ledger);
            accounting.initialize();
        }
        let active_dir = root.join("active");
        ensure_private_dir(&active_dir).unwrap();
        let active = active_dir.join("00000001.log");
        let active_file = std::fs::File::create(&active).unwrap();
        lock_spool_ledger(&ledger).register_active(&active);

        let sentinel = make_sentinel();
        let mut state = test_state();
        state.busy = true;
        state.current_run = Some(CurrentRun {
            sentinel: sentinel.clone(),
            resync: None,
        });
        state.spool_file = Some(SpoolWriter::with_accounting(
            active_file,
            active.clone(),
            128,
            ledger,
        ));

        ingest(
            &mut state,
            format!("{}\r\n\r\n{sentinel}0{sentinel}\r\n", "x".repeat(256)).as_bytes(),
        );

        assert!(!state.busy, "marker handling must survive cleanup failure");
        assert_eq!(state.last_result.as_ref().unwrap().exit_code, Some(0));
        assert!(!ring_contents(&state).is_empty());
        assert_eq!(std::fs::metadata(&active).unwrap().len(), 0);
        std::fs::set_permissions(&history_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn sftp_config_replaces_the_short_default_with_far_future_deadline() {
        let config = sftp_client_config();
        assert_eq!(config.request_timeout_secs, u64::MAX);
        assert!(
            tokio::time::Instant::now()
                .checked_add(Duration::from_secs(config.request_timeout_secs))
                .is_none(),
            "Tokio must route the maximum duration to its far-future path"
        );
    }
}
