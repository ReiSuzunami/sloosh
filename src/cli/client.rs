//! Client-side connection logic: connect to the daemon, and auto-spawn it
//! detached when it isn't running (docs/internals/architecture.md).
//!
//! Concurrent auto-spawn races are resolved by bind atomicity in
//! `transport::unix::bind`: if two CLI invocations both fail to connect and
//! both spawn a daemon, only one wins the bind; the other daemon process
//! exits quietly and this retry loop just keeps polling `connect` until
//! whichever one won is ready.

use crate::proto::{Request, Response, StatusReply, WIRE_PROTOCOL_VERSION};
use crate::transport::Channel;
use crate::transport::unix::{self, UnixChannel};
use anyhow::Context;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_ATTEMPTS: u32 = 12;
const INITIAL_DELAY: Duration = Duration::from_millis(50);
const MAX_DELAY: Duration = Duration::from_millis(1000);

/// Typed local-daemon client shared by CLI and desktop adapters.
///
/// The daemon executable is explicit because a bundled GUI authenticates and
/// starts `Contents/Helpers/sloosh`, not its own Tauri executable.
#[derive(Debug, Clone)]
pub struct DaemonClient {
    socket_path: PathBuf,
    daemon_executable: PathBuf,
}

impl DaemonClient {
    pub fn new(socket_path: PathBuf, daemon_executable: PathBuf) -> Self {
        Self {
            socket_path,
            daemon_executable,
        }
    }

    pub async fn request(&self, request: &Request) -> anyhow::Result<Response> {
        let mut channel =
            connect_or_spawn_with_executable(&self.socket_path, &self.daemon_executable).await?;
        channel.send(request).await?;
        channel
            .recv::<Response>()
            .await?
            .ok_or_else(|| anyhow::anyhow!("daemon closed connection without replying"))
    }

    pub async fn status(&self) -> anyhow::Result<StatusReply> {
        match self.request(&Request::Status).await? {
            Response::Status(status) => Ok(status),
            Response::Error { message } => anyhow::bail!("daemon status failed: {message}"),
            response => anyhow::bail!("daemon returned {response:?} instead of status"),
        }
    }
}

/// Connect to the daemon, auto-spawning it (detached, logging to
/// `~/.sloosh/daemon.log`) if it isn't reachable yet.
pub async fn connect_or_spawn(socket_path: &Path) -> anyhow::Result<UnixChannel> {
    let executable = std::env::current_exe().context(
        "failed to resolve sloosh's own executable path (needed to authenticate the daemon)",
    )?;
    connect_or_spawn_with_executable(socket_path, &executable).await
}

async fn connect_or_spawn_with_executable(
    socket_path: &Path,
    daemon_executable: &Path,
) -> anyhow::Result<UnixChannel> {
    match UnixChannel::connect_verified(socket_path, daemon_executable).await {
        Ok(chan) => return verify_wire_protocol(chan, socket_path).await,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(untrusted_daemon_error(socket_path, e));
        }
        Err(_) => {}
    }
    spawn_daemon_detached_with_executable(socket_path, daemon_executable)?;
    wait_for_daemon_with_executable(socket_path, daemon_executable).await
}

/// Poll `connect` with exponential backoff until it succeeds or we give up.
pub async fn wait_for_daemon(socket_path: &Path) -> anyhow::Result<UnixChannel> {
    let executable = std::env::current_exe().context(
        "failed to resolve sloosh's own executable path (needed to authenticate the daemon)",
    )?;
    wait_for_daemon_with_executable(socket_path, &executable).await
}

async fn wait_for_daemon_with_executable(
    socket_path: &Path,
    daemon_executable: &Path,
) -> anyhow::Result<UnixChannel> {
    let mut delay = INITIAL_DELAY;
    let mut last_err = None;
    for _ in 0..MAX_ATTEMPTS {
        tokio::time::sleep(delay).await;
        match UnixChannel::connect_verified(socket_path, daemon_executable).await {
            Ok(chan) => return verify_wire_protocol(chan, socket_path).await,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(untrusted_daemon_error(socket_path, e));
            }
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

pub(super) fn untrusted_daemon_error(socket_path: &Path, source: std::io::Error) -> anyhow::Error {
    anyhow::Error::new(source).context(format!(
        "refusing to use the daemon socket at {} because its server identity could not be verified",
        socket_path.display()
    ))
}

/// Verify the daemon before this channel carries an ordinary request. Exact
/// matching is required because SFTP transfers switch from NDJSON control
/// messages to raw frames mid-connection.
async fn verify_wire_protocol(
    mut chan: UnixChannel,
    socket_path: &Path,
) -> anyhow::Result<UnixChannel> {
    chan.send(&Request::Status).await.with_context(|| {
        format!(
            "failed to ask daemon at {} for its wire protocol",
            socket_path.display()
        )
    })?;

    let reply = chan.recv::<Response>().await.with_context(|| {
        format!(
            "failed to read wire protocol from daemon at {}",
            socket_path.display()
        )
    })?;
    let status = match reply {
        Some(Response::Status(status)) => status,
        Some(Response::Error { message }) => {
            anyhow::bail!("daemon refused protocol check: {message}")
        }
        Some(other) => anyhow::bail!(
            "daemon returned {other:?} during protocol check; stop it when ready with \
             `sloosh daemon stop`, then retry"
        ),
        None => anyhow::bail!(
            "daemon closed the connection during protocol check; stop/restart it when ready \
             with `sloosh daemon stop`, then retry"
        ),
    };

    if status.wire_protocol != WIRE_PROTOCOL_VERSION {
        anyhow::bail!(
            "incompatible sloosh daemon at {}: daemon {} speaks wire protocol {}, but this \
             CLI requires {}. Refusing to mix transfer framing. Stop it when ready with \
             `sloosh daemon stop`, then retry; stopping the daemon ends its active sessions \
             and forwards",
            socket_path.display(),
            status.version,
            status.wire_protocol,
            WIRE_PROTOCOL_VERSION,
        );
    }

    chan.send(&Request::Hello {
        wire_protocol: WIRE_PROTOCOL_VERSION,
    })
    .await
    .context("failed to send protocol handshake to daemon")?;
    match chan
        .recv::<Response>()
        .await
        .context("failed to read protocol handshake reply from daemon")?
    {
        Some(Response::ProtocolReady { wire_protocol })
            if wire_protocol == WIRE_PROTOCOL_VERSION => {}
        Some(Response::ProtocolReady { wire_protocol }) => anyhow::bail!(
            "daemon acknowledged wire protocol {wire_protocol}, but this CLI requires \
             {WIRE_PROTOCOL_VERSION}; stop it when ready with `sloosh daemon stop`, then retry"
        ),
        Some(Response::Error { message }) => anyhow::bail!(
            "daemon rejected wire protocol handshake: {message}. Stop it when ready with \
             `sloosh daemon stop`, then retry"
        ),
        Some(other) => anyhow::bail!(
            "daemon returned {other:?} during protocol handshake; stop it when ready with \
             `sloosh daemon stop`, then retry"
        ),
        None => anyhow::bail!(
            "daemon closed the connection during protocol handshake; stop/restart it when ready \
             with `sloosh daemon stop`, then retry"
        ),
    }

    Ok(chan)
}

/// Fork/exec `sloosh daemon run`, detached from this process's session, with
/// stdio wired to `~/.sloosh/daemon.log`.
pub fn spawn_daemon_detached(socket_path: &Path) -> anyhow::Result<()> {
    let exe = std::env::current_exe().context(
        "failed to resolve sloosh's own executable path (needed to auto-start the daemon)",
    )?;
    spawn_daemon_detached_with_executable(socket_path, &exe)
}

fn spawn_daemon_detached_with_executable(
    socket_path: &Path,
    executable: &Path,
) -> anyhow::Result<()> {
    let log_path = unix::daemon_log_path();
    let log_file = open_daemon_log(&log_path)?;
    let stdout = log_file
        .try_clone()
        .context("failed to duplicate daemon log file handle")?;

    let mut cmd = std::process::Command::new(executable);
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
        .with_context(|| format!("failed to spawn `{} daemon run`", executable.display()))?;
    Ok(())
}

fn open_daemon_log(path: &Path) -> anyhow::Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        unix::ensure_private_dir(parent)
            .with_context(|| format!("failed to secure {}", parent.display()))?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to open daemon log at {}", path.display()))?;
    unix::clear_extended_acl(&file)
        .with_context(|| format!("failed to clear daemon log ACL at {}", path.display()))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to secure daemon log at {}", path.display()))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::StatusReply;
    use crate::transport::BindOutcome;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_SOCKET_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_socket_path(tag: &str) -> std::path::PathBuf {
        let id = NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "sloosh-client-protocol-{tag}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create private test directory");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("secure private test directory");
        dir.join("sloosh.sock")
    }

    fn spawn_status_server(socket_path: &Path, wire_protocol: u32) -> tokio::task::JoinHandle<()> {
        let listener = match unix::bind(socket_path).expect("bind test socket") {
            BindOutcome::Bound(listener) => listener,
            BindOutcome::AlreadyRunning => panic!("test socket unexpectedly in use"),
        };
        tokio::spawn(async move {
            let mut chan = listener.accept().await.expect("accept client");
            assert_eq!(
                chan.recv::<Request>().await.expect("receive Status"),
                Some(Request::Status)
            );
            chan.send(&Response::Status(StatusReply {
                pid: std::process::id(),
                version: "legacy-test".to_string(),
                wire_protocol,
                uptime_secs: 0,
                ..StatusReply::default()
            }))
            .await
            .expect("send Status reply");
            if wire_protocol == WIRE_PROTOCOL_VERSION {
                assert_eq!(
                    chan.recv::<Request>().await.expect("receive Hello"),
                    Some(Request::Hello {
                        wire_protocol: WIRE_PROTOCOL_VERSION,
                    })
                );
                chan.send(&Response::ProtocolReady {
                    wire_protocol: WIRE_PROTOCOL_VERSION,
                })
                .await
                .expect("send protocol-ready reply");
            }
        })
    }

    fn spawn_ready_status_server(socket_path: &Path) -> tokio::task::JoinHandle<()> {
        let listener = match unix::bind(socket_path).expect("bind test socket") {
            BindOutcome::Bound(listener) => listener,
            BindOutcome::AlreadyRunning => panic!("test socket unexpectedly in use"),
        };
        tokio::spawn(async move {
            let mut chan = listener.accept().await.expect("accept client");
            assert_eq!(
                chan.recv::<Request>().await.expect("receive Status"),
                Some(Request::Status)
            );
            chan.send(&Response::Status(StatusReply {
                pid: 4242,
                version: "test-daemon".to_string(),
                wire_protocol: WIRE_PROTOCOL_VERSION,
                uptime_secs: 17,
                ..StatusReply::default()
            }))
            .await
            .expect("send Status reply");
            assert_eq!(
                chan.recv::<Request>().await.expect("receive Hello"),
                Some(Request::Hello {
                    wire_protocol: WIRE_PROTOCOL_VERSION,
                })
            );
            chan.send(&Response::ProtocolReady {
                wire_protocol: WIRE_PROTOCOL_VERSION,
            })
            .await
            .expect("send protocol-ready reply");
            assert_eq!(
                chan.recv::<Request>().await.expect("receive typed status"),
                Some(Request::Status)
            );
            chan.send(&Response::Status(StatusReply {
                pid: 4242,
                version: "test-daemon".to_string(),
                wire_protocol: WIRE_PROTOCOL_VERSION,
                uptime_secs: 17,
                ..StatusReply::default()
            }))
            .await
            .expect("send typed status reply");
        })
    }

    #[tokio::test]
    async fn daemon_client_returns_typed_status_from_selected_executable() {
        let socket_path = temp_socket_path("ts");
        let server = spawn_ready_status_server(&socket_path);
        let daemon_executable = std::env::current_exe().expect("current executable");
        let client = DaemonClient::new(socket_path.clone(), daemon_executable);

        let status = client.status().await.expect("typed daemon status");

        assert_eq!(status.pid, 4242);
        assert_eq!(status.version, "test-daemon");
        assert_eq!(status.uptime_secs, 17);
        server.await.expect("server task");
        let _ = std::fs::remove_dir_all(socket_path.parent().expect("socket parent"));
    }

    #[cfg(target_os = "macos")]
    fn add_everyone_read_acl(path: &Path) {
        let status = std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg("everyone allow read")
            .arg(path)
            .status()
            .expect("run chmod +a");
        assert!(status.success(), "chmod +a should add test ACL");
    }

    #[test]
    fn daemon_log_creation_and_repair_use_private_modes() {
        let root =
            std::env::temp_dir().join(format!("sloosh-client-log-test-{}", std::process::id()));
        let home = root.join("home");
        let log_path = home.join("daemon.log");
        let fresh_log_path = home.join("fresh-daemon.log");
        std::fs::create_dir_all(&home).expect("create test home");
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755))
            .expect("set permissive home mode");
        std::fs::write(&log_path, b"old log\n").expect("create existing log");
        std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o644))
            .expect("set permissive log mode");
        #[cfg(target_os = "macos")]
        {
            add_everyone_read_acl(&home);
            add_everyone_read_acl(&log_path);
        }

        let file = open_daemon_log(&log_path).expect("open and repair daemon log");

        let home_mode = std::fs::metadata(&home)
            .expect("home metadata")
            .permissions()
            .mode()
            & 0o777;
        let log_mode = std::fs::metadata(&log_path)
            .expect("log metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(home_mode, 0o700);
        assert_eq!(log_mode, 0o600);
        #[cfg(target_os = "macos")]
        {
            assert!(
                !unix::has_extended_acl_for_test(&file).expect("read repaired log ACL"),
                "daemon log must not retain an extended ACL"
            );
            let directory = std::fs::File::open(&home).expect("open repaired home");
            assert!(
                !unix::has_extended_acl_for_test(&directory).expect("read repaired home ACL"),
                "sloosh home must not retain an extended ACL"
            );
        }
        drop(file);

        drop(open_daemon_log(&fresh_log_path).expect("create private daemon log"));
        let fresh_log_mode = std::fs::metadata(&fresh_log_path)
            .expect("fresh log metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(fresh_log_mode, 0o600);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn connect_or_spawn_rejects_legacy_wire_protocol() {
        let socket_path = temp_socket_path("legacy");
        let server = spawn_status_server(&socket_path, 0);

        let error = match connect_or_spawn(&socket_path).await {
            Ok(_) => panic!("legacy daemon must be rejected"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(message.contains("wire protocol 0"), "{message}");
        assert!(
            message.contains(&format!("requires {WIRE_PROTOCOL_VERSION}")),
            "{message}"
        );
        assert!(message.contains("sloosh daemon stop"), "{message}");
        assert!(message.contains("sessions and forwards"), "{message}");

        server.await.expect("status server should exit cleanly");
        let _ = std::fs::remove_dir_all(socket_path.parent().expect("socket parent"));
    }

    #[tokio::test]
    async fn wait_for_daemon_accepts_matching_wire_protocol() {
        let socket_path = temp_socket_path("matching");
        let server = spawn_status_server(&socket_path, WIRE_PROTOCOL_VERSION);

        let chan = wait_for_daemon(&socket_path)
            .await
            .expect("matching daemon should be accepted");
        drop(chan);

        server.await.expect("status server should exit cleanly");
        let _ = std::fs::remove_dir_all(socket_path.parent().expect("socket parent"));
    }
}
