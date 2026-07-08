//! Unix domain socket transport: the one active implementation of
//! [`super::Channel`] for macOS + Linux (DESIGN.md §2, §8). All
//! platform-specific bytes (peer credential lookups, socket path
//! conventions) live in this file, gated by `cfg(target_os = ...)`.

use super::{BindOutcome, Channel};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::io::BufReader;
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

/// Errors from setting up the listening side of the socket. Kept distinct
/// from plain `io::Error` so callers can render self-teaching messages
/// (DESIGN.md §7) without re-parsing error text.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("failed to create directory {path}: {source}")]
    CreateDir { path: PathBuf, source: io::Error },
    #[error("failed to bind sloosh socket at {path}: {source}")]
    Bind { path: PathBuf, source: io::Error },
    #[error("failed to set permissions on {path}: {source}")]
    Permissions { path: PathBuf, source: io::Error },
}

/// `~/.sloosh` — home for the daemon log, socket (on macOS), audit log,
/// vault, known_hosts and spool. `$SLOOSH_HOME` always wins if set (same
/// override pattern as `$SLOOSH_SOCKET` below — used by tests so a live-SSH
/// integration test run can't ever touch the real developer's vault or
/// known_hosts), otherwise resolved from `$HOME`, which is always set on the
/// Unix-only platforms this milestone targets.
pub fn sloosh_home() -> PathBuf {
    if let Ok(p) = std::env::var("SLOOSH_HOME") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".sloosh")
}

/// Where the daemon appends its logs when auto-spawned/detached.
pub fn daemon_log_path() -> PathBuf {
    sloosh_home().join("daemon.log")
}

/// Resolve the daemon socket path: `$SLOOSH_SOCKET` always wins (used by
/// tests and anyone running multiple daemons side by side), otherwise the
/// per-OS convention from DESIGN.md §2.
pub fn resolve_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("SLOOSH_SOCKET") {
        return PathBuf::from(p);
    }
    default_socket_path()
}

#[cfg(target_os = "linux")]
fn default_socket_path() -> PathBuf {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(runtime_dir).join("sloosh.sock")
}

#[cfg(target_os = "macos")]
fn default_socket_path() -> PathBuf {
    sloosh_home().join("sloosh.sock")
}

/// One end of a connected Unix domain socket, framed as NDJSON.
pub struct UnixChannel {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    fd: RawFd,
}

impl UnixChannel {
    fn from_stream(stream: UnixStream) -> Self {
        let fd = stream.as_raw_fd();
        let (read_half, writer) = stream.into_split();
        Self {
            reader: BufReader::new(read_half),
            writer,
            fd,
        }
    }

    /// Connect to the daemon's socket as a client.
    pub async fn connect(path: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(path).await?;
        Ok(Self::from_stream(stream))
    }
}

impl Channel for UnixChannel {
    fn peer_pid(&self) -> io::Result<Option<u32>> {
        peer_pid_impl(self.fd)
    }

    async fn send<T>(&mut self, msg: &T) -> io::Result<()>
    where
        T: Serialize + Sync,
    {
        crate::proto::write_message(&mut self.writer, msg).await
    }

    async fn recv<T>(&mut self) -> io::Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        crate::proto::read_message(&mut self.reader).await
    }
}

/// Server-side listener wrapping a bound, mode-0600 Unix domain socket.
pub struct UnixListener {
    inner: tokio::net::UnixListener,
    path: PathBuf,
}

impl UnixListener {
    pub async fn accept(&self) -> io::Result<UnixChannel> {
        let (stream, _addr) = self.inner.accept().await?;
        Ok(UnixChannel::from_stream(stream))
    }
}

impl Drop for UnixListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Bind the daemon socket at `path`.
///
/// Ensures the parent directory exists, sets mode 0600, and cleans up a
/// stale socket file left behind by an unclean shutdown: if the path
/// already exists, we first try to *connect* to it — success means a live
/// daemon owns it ([`BindOutcome::AlreadyRunning`]); failure means the file
/// is stale, so we remove it and bind fresh.
pub fn bind(path: &Path) -> Result<BindOutcome<UnixListener>, TransportError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| TransportError::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    match std::os::unix::net::UnixListener::bind(path) {
        Ok(std_listener) => finish_bind(std_listener, path),
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Ok(BindOutcome::AlreadyRunning);
            }
            std::fs::remove_file(path).map_err(|source| TransportError::Bind {
                path: path.to_path_buf(),
                source,
            })?;
            let std_listener = std::os::unix::net::UnixListener::bind(path).map_err(|source| {
                TransportError::Bind {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            finish_bind(std_listener, path)
        }
        Err(source) => Err(TransportError::Bind {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn finish_bind(
    std_listener: std::os::unix::net::UnixListener,
    path: &Path,
) -> Result<BindOutcome<UnixListener>, TransportError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|source| {
        TransportError::Permissions {
            path: path.to_path_buf(),
            source,
        }
    })?;
    std_listener
        .set_nonblocking(true)
        .map_err(|source| TransportError::Bind {
            path: path.to_path_buf(),
            source,
        })?;
    let inner = tokio::net::UnixListener::from_std(std_listener).map_err(|source| {
        TransportError::Bind {
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(BindOutcome::Bound(UnixListener {
        inner,
        path: path.to_path_buf(),
    }))
}

#[cfg(target_os = "linux")]
fn peer_pid_impl(fd: RawFd) -> io::Result<Option<u32>> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Some(cred.pid as u32))
}

#[cfg(target_os = "macos")]
fn peer_pid_impl(fd: RawFd) -> io::Result<Option<u32>> {
    // `sys/un.h` on Darwin: SOL_LOCAL = 0, LOCAL_PEERPID = 0x2. Stable ABI,
    // but not exposed as constants by the `libc` crate on this target.
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERPID: libc::c_int = 0x002;

    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Some(pid as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_creates_parent_dir_and_mode_0600() {
        let dir = std::env::temp_dir().join(format!("sloosh-unix-test-{}", std::process::id()));
        let sock = dir.join("nested").join("sloosh.sock");
        let outcome = bind(&sock).expect("bind should succeed");
        let BindOutcome::Bound(listener) = outcome else {
            panic!("expected Bound, got AlreadyRunning");
        };
        let meta = std::fs::metadata(&sock).expect("socket file should exist");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        drop(listener);
        assert!(
            !sock.exists(),
            "listener drop should remove the socket file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn connect_and_status_round_trip_over_socket() {
        let dir = std::env::temp_dir().join(format!("sloosh-unix-test2-{}", std::process::id()));
        let sock = dir.join("sloosh.sock");
        let BindOutcome::Bound(listener) = bind(&sock).expect("bind") else {
            panic!("expected Bound")
        };

        let server = tokio::spawn(async move {
            let mut chan = listener.accept().await.expect("accept");
            let req: crate::proto::Request = chan.recv().await.expect("recv").expect("some");
            assert_eq!(req, crate::proto::Request::Status);
            chan.send(&crate::proto::Response::Ok).await.expect("send");
        });

        let mut client = UnixChannel::connect(&sock).await.expect("connect");
        client
            .send(&crate::proto::Request::Status)
            .await
            .expect("send");
        let resp: crate::proto::Response = client.recv().await.expect("recv").expect("some");
        assert_eq!(resp, crate::proto::Response::Ok);

        server.await.expect("server task");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
