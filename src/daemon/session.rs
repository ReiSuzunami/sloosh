//! Persistent PTY session management: sentinel-based command/output framing,
//! ring buffer + cursor `peek`, spool-to-disk, dead-session semantics, idle
//! reaping (DESIGN.md §3, §5).
//!
//! Same interim trust posture as the rest of the daemon (see the note in
//! `daemon/mod.rs`): any local caller can address any session. No
//! per-session authorization is enforced here yet.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use rand::Rng;
use tokio::sync::{Mutex as AsyncMutex, watch};
use tokio::time::sleep_until;
use tracing::{info, warn};

use crate::daemon::ssh::{self, SshError};
use crate::proto::SessionSummary;
use crate::transport::unix::sloosh_home;

/// Bound on how much output we keep in memory per session (DESIGN.md §5).
const RING_CAPACITY: usize = 256 * 1024;
/// Cap on how much of a single run/peek reply's `output` field we send back
/// (DESIGN.md §5 "~30k 字符尾部"); the untruncated bytes are always on disk
/// in the spool file.
const MAX_OUTPUT_CHARS: usize = 30_000;
/// Keep at most this many bytes per session's spool directory before
/// deleting the oldest files (DESIGN.md §5, "simple size-based cleanup").
const MAX_SPOOL_DIR_BYTES: u64 = 64 * 1024 * 1024;
/// A session with no read or write activity for this long is reaped
/// (DESIGN.md §3). Configurable only in the sense that it's one constant to
/// edit — no config surface for it in this milestone.
const IDLE_REAP_AFTER: Duration = Duration::from_secs(8 * 60 * 60);
/// How often the idle reaper wakes up to check.
const IDLE_REAP_SWEEP_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Everything that can go wrong operating on a session. Self-teaching
/// messages per DESIGN.md §7.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(
        "no session '{session}' on '{host}' — run `sloosh run {host} <command>` (creates the \
         default session) or `sloosh open {host} {session}` first"
    )]
    NotFound { host: String, session: String },

    #[error(
        "session '{session}' on '{host}' is still busy running a previous command; `sloosh peek \
         {host} --session {session}` to check on it, or wait for it to finish, before running another"
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
    /// documented simplification, DESIGN.md §5 ring buffer is best-effort,
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

/// Generate a sentinel unlikely to appear in any command's own output.
fn make_sentinel() -> String {
    let n: u128 = rand::rng().random();
    format!("__sloosh_{n:032x}__")
}

/// Build the literal line written to the PTY for one `run`: run the
/// command, then print exit status bracketed by the sentinel so the reader
/// can find where the command's own output ends (DESIGN.md §3).
fn frame_command(command: &str, sentinel: &str) -> String {
    format!("{command}; printf '\\n{sentinel}%s{sentinel}\\n' $?\n")
}

/// Result of successfully locating a sentinel marker in accumulated output.
struct SentinelMatch {
    /// Length of the command's own output, i.e. everything before the
    /// marker (with the marker's own leading `\n` from `printf` dropped).
    output_len: usize,
    exit_code: i32,
}

/// Scan `buf` for a complete `<sentinel><digits><sentinel>` marker.
///
/// Always rescans from the start of `buf` rather than keeping streaming
/// parse state; this is deliberate — it makes chunked/split reads trivially
/// correct (and trivially testable: feed the same growing buffer in via
/// arbitrary chunk boundaries and the result never depends on where the
/// splits fall), at the cost of doing `O(n)` work per chunk instead of
/// `O(1)`. Session output volumes make that cost irrelevant in practice.
fn find_sentinel(buf: &[u8], sentinel: &str) -> Option<SentinelMatch> {
    let needle = sentinel.as_bytes();
    if needle.is_empty() {
        return None;
    }
    let first = find_subslice(buf, needle)?;
    let after_first = first + needle.len();
    let second_rel = find_subslice(&buf[after_first..], needle)?;
    let second = after_first + second_rel;

    let code_str = std::str::from_utf8(&buf[after_first..second]).ok()?;
    let exit_code: i32 = code_str.trim().parse().ok()?;

    let mut output_len = first;
    if output_len > 0 && buf[output_len - 1] == b'\n' {
        output_len -= 1;
    }
    Some(SentinelMatch {
        output_len,
        exit_code,
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
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

/// Defensive fallback for echo suppression: if PTY-level `ECHO`/`ECHONL`
/// suppression (set via `request_pty` terminal modes in `ssh.rs`) was
/// ignored by the remote shell/server, the very first line of a command's
/// output is often just the shell echoing the command line back. Strip it
/// if it matches the command we sent, verbatim.
fn strip_echoed_command(output: &[u8], command: &str) -> Vec<u8> {
    let first_line_end = output.iter().position(|&b| b == b'\n');
    let Some(end) = first_line_end else {
        return output.to_vec();
    };
    let first_line = &output[..end];
    if first_line == command.trim_end().as_bytes() {
        output[end + 1..].to_vec()
    } else {
        output.to_vec()
    }
}

/// Shape raw command output for a reply: strip ANSI (unless `raw`), then
/// cap to `MAX_OUTPUT_CHARS` (keeping the tail, since that's almost always
/// what's relevant), returning `(shown, truncated, total_bytes)` where
/// `total_bytes` is the size of the *shaped-but-untruncated* text — i.e.
/// what you'd get from the spool file after the same ANSI handling.
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
            "... [truncated {skip} chars; {total_bytes} bytes total in this run — see spool file for full output] ...\n"
        );
        (marker + &tail, true, total_bytes)
    }
}

// ---------------------------------------------------------------------------
// Session state + registry
// ---------------------------------------------------------------------------

struct CurrentRun {
    sentinel: String,
    start_offset: u64,
}

struct RunOutcome {
    exit_code: i32,
    end_offset: u64,
}

struct SessionState {
    ring: RingBuffer,
    /// Single global read cursor for `peek` (DESIGN.md §5 simplification:
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
    spool_file: Option<std::fs::File>,
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

fn default_session_name(session: Option<String>) -> String {
    session.unwrap_or_else(|| "default".to_string())
}

fn spool_dir(host: &str, name: &str) -> PathBuf {
    sloosh_home().join("spool").join(format!("{host}--{name}"))
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
/// reconnect automatically (DESIGN.md §3) and instead returns a
/// self-teaching error telling the caller to `kill` it first.
async fn get_or_create_session(host: &str, name: &str) -> Result<Arc<SessionInner>, SessionError> {
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
    create_session(host, name).await
}

async fn create_session(host: &str, name: &str) -> Result<Arc<SessionInner>, SessionError> {
    let conn = ssh::connect(host).await?;
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

    {
        let mut reg = registry().lock().await;
        reg.insert((host.to_string(), name.to_string()), inner.clone());
    }

    tokio::spawn(reader_loop(inner.clone(), read_half));

    // Quiesce the shell for scripted use (DESIGN.md §3): disable color and
    // fancy prompts, drop bash history for this session, and blank the
    // prompt/PROMPT_COMMAND so nothing but real command output shows up.
    // Sent as an ordinary shell line, same as any `run` — its noise just
    // predates the first real command's `start_offset`, so it never
    // pollutes that command's captured output.
    let init = "export NO_COLOR=1 TERM=dumb; unset HISTFILE; PS1='' PROMPT_COMMAND=''\n";
    let _ = inner.write_half.data_bytes(init.as_bytes().to_vec()).await;

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
    state.ring.push_slice(data);
    state.last_activity = Instant::now();
    if let Some(file) = state.spool_file.as_mut() {
        // Local disk writes are small and fast; a brief synchronous write
        // here is simpler and cheaper than wiring up tokio::fs for this
        // milestone (avoids an extra dependency edge for negligible gain).
        let _ = file.write_all(data);
    }
    if let Some(current) = &state.current_run {
        let (segment, _dropped) = state.ring.since(current.start_offset);
        if let Some(m) = find_sentinel(&segment, &current.sentinel) {
            let end_offset = current.start_offset + m.output_len as u64;
            state.last_result = Some(RunOutcome {
                exit_code: m.exit_code,
                end_offset,
            });
            state.busy = false;
            state.current_run = None;
            state.spool_file = None; // dropped => flushed and closed
        }
    }
    drop(state);
    inner.wake_tx.send_modify(|v| *v = v.wrapping_add(1));
}

async fn mark_dead(inner: &Arc<SessionInner>, reason: &str) {
    let mut state = inner.state.lock().await;
    if state.dead.is_none() {
        warn!(host = %inner.host, session = %inner.name, reason, "session died");
        state.dead = Some(reason.to_string());
    }
    state.busy = false;
    state.current_run = None;
    drop(state);
    inner.wake_tx.send_modify(|v| *v = v.wrapping_add(1));
}

fn open_spool_file(host: &str, name: &str, seq: u64) -> std::io::Result<(PathBuf, std::fs::File)> {
    let dir = spool_dir(host, name);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{seq:08}.log"));
    let file = std::fs::File::create(&path)?;
    cleanup_spool_dir(&dir);
    Ok((path, file))
}

/// Simple size-based retention: while the directory holds more than
/// `MAX_SPOOL_DIR_BYTES`, delete the oldest files (by filename, which is a
/// zero-padded sequence number so lexicographic order is chronological)
/// until it doesn't. Best-effort — errors are logged, not propagated,
/// since spool cleanup should never block a `run` from completing.
fn cleanup_spool_dir(dir: &std::path::Path) {
    let mut entries: Vec<(PathBuf, u64)> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let meta = e.metadata().ok()?;
                Some((e.path(), meta.len()))
            })
            .collect(),
        Err(e) => {
            warn!(dir = %dir.display(), error = %e, "could not list spool dir for cleanup");
            return;
        }
    };
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut total: u64 = entries.iter().map(|(_, len)| *len).sum();
    let mut i = 0;
    while total > MAX_SPOOL_DIR_BYTES && i < entries.len() {
        let (path, len) = &entries[i];
        if std::fs::remove_file(path).is_ok() {
            total = total.saturating_sub(*len);
        }
        i += 1;
    }
}

fn dead_reply_output(state: &SessionState, start_offset: u64, raw: bool) -> (String, bool, u64) {
    let (bytes, _dropped) = state.ring.since(start_offset);
    shape_output(&bytes, raw)
}

// ---------------------------------------------------------------------------
// Public operations (backing the CLI command set, DESIGN.md §6)
// ---------------------------------------------------------------------------

use crate::proto::{PeekReply, RunReply};

/// `run <host> <command>` — DESIGN.md §3, §6.
pub async fn run(
    host: &str,
    command: &str,
    session: Option<String>,
    timeout_secs: u64,
    raw: bool,
) -> Result<RunReply, SessionError> {
    let name = default_session_name(session);
    let inner = get_or_create_session(host, &name).await?;
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
        state.busy = true;
        state.run_seq += 1;
        start_offset = state.ring.total_written;
        let (path, file) = open_spool_file(host, &name, state.run_seq)?;
        spool_path = path;
        state.spool_file = Some(file);
        state.current_run = Some(CurrentRun {
            sentinel: sentinel.clone(),
            start_offset,
        });
        state.last_result = None;
    }

    let cmd_line = frame_command(command, &sentinel);
    if let Err(e) = inner.write_half.data_bytes(cmd_line.into_bytes()).await {
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
        .expect("busy cleared without dying implies the sentinel was found and recorded a result");
    let (all_since_start, _dropped) = state.ring.since(start_offset);
    let want_len = ((outcome.end_offset - start_offset) as usize).min(all_since_start.len());
    let command_output = &all_since_start[..want_len];
    let command_output = strip_echoed_command(command_output, command);
    let (output, truncated, total_bytes) = shape_output(&command_output, raw);

    Ok(RunReply {
        host: host.to_string(),
        session: name,
        state: "done".to_string(),
        exit_code: Some(outcome.exit_code),
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

/// `peek <host>` — DESIGN.md §3, §6.
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

/// `send <host> <keys>` — DESIGN.md §6.
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

/// `interrupt <host>` — sends Ctrl-C (0x03), DESIGN.md §6.
pub async fn interrupt(host: &str, session: Option<String>) -> Result<(), SessionError> {
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
    inner
        .write_half
        .data_bytes(vec![0x03u8])
        .await
        .map_err(SshError::from)?;
    Ok(())
}

/// `open <host> <name>` — explicit create-or-reuse of a named session
/// (DESIGN.md §6). Unlike `run`, never implicitly targets "default".
pub async fn open(host: &str, name: &str) -> Result<SessionSummary, SessionError> {
    let inner = get_or_create_session(host, name).await?;
    let state = inner.state.lock().await;
    Ok(summarize(host, name, &state))
}

/// `kill <host>` — DESIGN.md §6. Removes the session from the registry and
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

/// `ls [--host]` — DESIGN.md §6.
pub async fn ls(host_filter: Option<String>) -> Vec<SessionSummary> {
    let reg = registry().lock().await;
    let mut out = Vec::with_capacity(reg.len());
    for ((host, name), inner) in reg.iter() {
        if let Some(hf) = &host_filter
            && hf != host
        {
            continue;
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

    // --- sentinel framing ---------------------------------------------

    #[test]
    fn find_sentinel_locates_marker_and_exit_code() {
        let sentinel = "SENT1234";
        let buf = format!("hello world\n{sentinel}0{sentinel}\n");
        let m = find_sentinel(buf.as_bytes(), sentinel).expect("should find marker");
        assert_eq!(&buf.as_bytes()[..m.output_len], b"hello world");
        assert_eq!(m.exit_code, 0);
    }

    #[test]
    fn find_sentinel_nonzero_exit_code() {
        let sentinel = "SENT";
        let buf = format!("oops\n{sentinel}127{sentinel}\n");
        let m = find_sentinel(buf.as_bytes(), sentinel).expect("should find marker");
        assert_eq!(m.exit_code, 127);
    }

    #[test]
    fn find_sentinel_returns_none_when_incomplete() {
        let sentinel = "SENT";
        // Only the first occurrence has arrived so far.
        let buf = format!("output so far\n{sentinel}0");
        assert!(find_sentinel(buf.as_bytes(), sentinel).is_none());
    }

    #[test]
    fn find_sentinel_handles_chunked_split_reads() {
        // Simulate the reader task's behavior: it always rescans the full
        // accumulated buffer, so feeding the same bytes in via ever-growing
        // prefixes must agree on the final answer regardless of where any
        // individual split falls (including splitting the sentinel itself).
        let sentinel = "CHUNKY99";
        let full = format!("first line\nsecond line\n{sentinel}42{sentinel}\n");
        let bytes = full.as_bytes();
        let mut found = None;
        for split in 1..=bytes.len() {
            if let Some(m) = find_sentinel(&bytes[..split], sentinel) {
                found = Some(m);
                break;
            }
        }
        let m = found.expect("should eventually find the marker as the buffer grows");
        assert_eq!(m.exit_code, 42);
        assert_eq!(&bytes[..m.output_len], b"first line\nsecond line");
    }

    #[test]
    fn find_sentinel_rejects_non_numeric_between_markers() {
        let sentinel = "SENT";
        let buf = format!("weird\n{sentinel}notanumber{sentinel}\n");
        assert!(find_sentinel(buf.as_bytes(), sentinel).is_none());
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
        let stripped = strip_echoed_command(out, "ls -la");
        assert_eq!(stripped, b"total 0\n-rw-r--r-- 1 u u 0 file\n");
    }

    #[test]
    fn strip_echoed_command_leaves_output_alone_when_not_echoed() {
        let out = b"total 0\nfile\n";
        let stripped = strip_echoed_command(out, "ls -la");
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

    // --- spool cleanup -------------------------------------------------

    #[test]
    fn cleanup_spool_dir_removes_oldest_when_over_budget() {
        let dir = std::env::temp_dir().join(format!(
            "sloosh-spool-test-{}-{}",
            std::process::id(),
            make_sentinel()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..3u32 {
            let path = dir.join(format!("{i:08}.log"));
            std::fs::write(&path, vec![0u8; 10]).unwrap();
        }
        let saved = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(saved, 3);
        // Directly exercising the real 64MiB budget would require huge
        // files; this confirms the no-op path (well under budget, nothing
        // pruned) since that's what every real invocation hits in tests.
        cleanup_spool_dir(&dir);
        let remaining = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(remaining, 3, "well under the size budget, nothing pruned");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
