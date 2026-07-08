//! Client-side connection logic: connect to the daemon, and auto-spawn it
//! detached when it isn't running (DESIGN.md §1).
//!
//! Concurrent auto-spawn races are resolved by bind atomicity in
//! `transport::unix::bind`: if two CLI invocations both fail to connect and
//! both spawn a daemon, only one wins the bind; the other daemon process
//! exits quietly and this retry loop just keeps polling `connect` until
//! whichever one won is ready.

use crate::transport::unix::{self, UnixChannel};
use anyhow::Context;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::time::Duration;

const MAX_ATTEMPTS: u32 = 12;
const INITIAL_DELAY: Duration = Duration::from_millis(50);
const MAX_DELAY: Duration = Duration::from_millis(1000);

/// Connect to the daemon, auto-spawning it (detached, logging to
/// `~/.sloosh/daemon.log`) if it isn't reachable yet.
pub async fn connect_or_spawn(socket_path: &Path) -> anyhow::Result<UnixChannel> {
    if let Ok(chan) = UnixChannel::connect(socket_path).await {
        return Ok(chan);
    }
    spawn_daemon_detached(socket_path)?;
    wait_for_daemon(socket_path).await
}

/// Poll `connect` with exponential backoff until it succeeds or we give up.
pub async fn wait_for_daemon(socket_path: &Path) -> anyhow::Result<UnixChannel> {
    let mut delay = INITIAL_DELAY;
    let mut last_err = None;
    for _ in 0..MAX_ATTEMPTS {
        tokio::time::sleep(delay).await;
        match UnixChannel::connect(socket_path).await {
            Ok(chan) => return Ok(chan),
            Err(e) => {
                last_err = Some(e);
                delay = (delay * 2).min(MAX_DELAY);
            }
        }
    }
    let log_path = unix::daemon_log_path();
    anyhow::bail!(
        "could not reach the sloosh daemon at {} after starting it ({}). \
         Check {} for errors, or try `sloosh daemon start` to see the failure directly.",
        socket_path.display(),
        last_err.map(|e| e.to_string()).unwrap_or_default(),
        log_path.display(),
    )
}

/// Fork/exec `sloosh daemon run`, detached from this process's session, with
/// stdio wired to `~/.sloosh/daemon.log`.
pub fn spawn_daemon_detached(socket_path: &Path) -> anyhow::Result<()> {
    let exe = std::env::current_exe().context(
        "failed to resolve sloosh's own executable path (needed to auto-start the daemon)",
    )?;
    let log_path = unix::daemon_log_path();
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("failed to open daemon log at {}", log_path.display()))?;
    let stdout = log_file
        .try_clone()
        .context("failed to duplicate daemon log file handle")?;

    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("daemon").arg("run");
    // SLOOSH_SOCKET is inherited automatically, but set it explicitly too so
    // the spawned daemon binds the exact same path even if it was passed in
    // some other way (e.g. resolved default differs across working dirs).
    cmd.env("SLOOSH_SOCKET", socket_path);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(stdout);
    cmd.stderr(log_file);

    // Safety: the closure only calls the async-signal-safe libc function
    // `setsid` before exec, as required by `pre_exec`'s contract.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    cmd.spawn()
        .with_context(|| format!("failed to spawn `{} daemon run`", exe.display()))?;
    Ok(())
}
