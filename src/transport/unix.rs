//! Unix domain socket transport: the one active implementation of
//! [`super::Channel`] for macOS + Linux (DESIGN.md §2, §8). All
//! platform-specific bytes (peer credential lookups, socket path
//! conventions) live in this file, gated by `cfg(target_os = ...)`.

use super::{BindOutcome, Channel, MAX_RAW_FRAME_BYTES};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
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
    #[error("failed to open private directory {path}: {source}")]
    OpenDirectory { path: PathBuf, source: io::Error },
    #[error("refusing to use {path} as a private directory: {reason}")]
    UnsafeDirectory { path: PathBuf, reason: &'static str },
    #[error(
        "refusing to use {path} as a private directory: owned by uid {actual_uid}, expected uid {expected_uid}"
    )]
    WrongOwner {
        path: PathBuf,
        actual_uid: u32,
        expected_uid: u32,
    },
}

/// `~/.sloosh` — home for the daemon log, socket (on macOS), audit log,
/// vault, known_hosts and spool. `$SLOOSH_HOME` always wins if set (same
/// override pattern as `$SLOOSH_SOCKET` below — used by tests so a live-SSH
/// integration test run can't ever touch the real developer's vault or
/// known_hosts), otherwise resolved from `$HOME`, which is always set on the
/// Unix-only platforms this milestone targets.
pub fn sloosh_home() -> PathBuf {
    if let Some(path) = std::env::var_os("SLOOSH_HOME") {
        return PathBuf::from(path);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".sloosh");
    }
    PathBuf::from("/tmp").join(format!("sloosh-{}", effective_uid()))
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
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !runtime_dir.is_empty() {
            return PathBuf::from(runtime_dir).join("sloosh.sock");
        }
    }
    linux_fallback_socket_path(effective_uid())
}

#[cfg(target_os = "linux")]
fn linux_fallback_socket_path(uid: u32) -> PathBuf {
    PathBuf::from("/tmp")
        .join(format!("sloosh-{uid}"))
        .join("sloosh.sock")
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

    /// Connect to the daemon's socket and verify that the server is this
    /// user's current sloosh executable.
    pub async fn connect(path: &Path) -> io::Result<Self> {
        let channel = Self::connect_unverified(path).await?;
        channel.verify_peer_identity().map_err(|source| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing untrusted sloosh daemon at {}: {source}",
                    path.display()
                ),
            )
        })?;
        Ok(channel)
    }

    /// Connect without authenticating the server process.
    ///
    /// This is only appropriate for in-process tests and liveness probes that
    /// never send credentials or privileged requests.
    pub async fn connect_unverified(path: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(path).await?;
        Ok(Self::from_stream(stream))
    }

    fn verify_peer_identity(&self) -> io::Result<()> {
        let expected_exe = std::fs::canonicalize(std::env::current_exe()?)?;
        self.verify_peer_identity_against(effective_uid(), &expected_exe)
    }

    fn verify_peer_identity_against(
        &self,
        expected_uid: u32,
        expected_exe: &Path,
    ) -> io::Result<()> {
        let credentials = peer_credentials_impl(self.fd)?;
        if credentials.uid != expected_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "socket peer uid {} does not match effective uid {expected_uid}",
                    credentials.uid
                ),
            ));
        }

        let peer_exe = peer_executable_path(credentials.pid)?;
        if peer_exe != expected_exe {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "socket peer executable {} does not match {}",
                    peer_exe.display(),
                    expected_exe.display()
                ),
            ));
        }
        Ok(())
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

    async fn send_raw_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        if frame.len() > MAX_RAW_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "raw frame is {} bytes, exceeds {} byte limit",
                    frame.len(),
                    MAX_RAW_FRAME_BYTES
                ),
            ));
        }

        let length = u32::try_from(frame.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "raw frame length exceeds u32")
        })?;
        self.writer.write_all(&length.to_be_bytes()).await?;
        self.writer.write_all(frame).await?;
        self.writer.flush().await
    }

    async fn recv_raw_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut header = [0_u8; size_of::<u32>()];
        self.reader.read_exact(&mut header).await?;
        let length = u32::from_be_bytes(header) as usize;
        if length == 0 {
            return Ok(None);
        }
        if length > MAX_RAW_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "raw frame declares {length} bytes, exceeds {MAX_RAW_FRAME_BYTES} byte limit"
                ),
            ));
        }

        let mut frame = vec![0_u8; length];
        self.reader.read_exact(&mut frame).await?;
        Ok(Some(frame))
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
        ensure_private_dir(parent)?;
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

/// Create or repair a sloosh-owned directory to mode 0700.
pub fn ensure_private_dir(path: &Path) -> Result<(), TransportError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .map_err(|source| TransportError::CreateDir {
            path: path.to_path_buf(),
            source,
        })?;

    let metadata = std::fs::symlink_metadata(path).map_err(|source| TransportError::CreateDir {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(TransportError::UnsafeDirectory {
            path: path.to_path_buf(),
            reason: "path is a symbolic link",
        });
    }
    if !metadata.is_dir() {
        return Err(TransportError::UnsafeDirectory {
            path: path.to_path_buf(),
            reason: "path is not a directory",
        });
    }

    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| TransportError::OpenDirectory {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata = directory
        .metadata()
        .map_err(|source| TransportError::OpenDirectory {
            path: path.to_path_buf(),
            source,
        })?;
    let expected_uid = effective_uid();
    let actual_uid = metadata.uid();
    if actual_uid != expected_uid {
        return Err(TransportError::WrongOwner {
            path: path.to_path_buf(),
            actual_uid,
            expected_uid,
        });
    }

    clear_extended_acl(&directory).map_err(|source| TransportError::Permissions {
        path: path.to_path_buf(),
        source,
    })?;
    directory
        .set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(|source| TransportError::Permissions {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(target_os = "macos")]
pub(crate) fn clear_extended_acl(file: &File) -> io::Result<()> {
    type Acl = *mut libc::c_void;
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;

    unsafe extern "C" {
        fn acl_init(count: libc::c_int) -> Acl;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
        fn acl_set_fd_np(fd: libc::c_int, acl: Acl, acl_type: libc::c_int) -> libc::c_int;
    }

    // SAFETY: `acl_init(0)` allocates an empty ACL with no caller-owned input.
    let acl = unsafe { acl_init(0) };
    if acl.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `acl` is live and owned by this function; `file` supplies a
    // valid descriptor for the duration of the call.
    let set_result = unsafe { acl_set_fd_np(file.as_raw_fd(), acl, ACL_TYPE_EXTENDED) };
    let set_error = (set_result != 0).then(io::Error::last_os_error);
    // SAFETY: `acl` came from `acl_init` and has not yet been freed.
    let free_result = unsafe { acl_free(acl) };
    if let Some(error) = set_error {
        return Err(error);
    }
    if free_result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn clear_extended_acl(_file: &File) -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
pub(crate) fn has_extended_acl_for_test(file: &File) -> io::Result<bool> {
    type Acl = *mut libc::c_void;
    type AclEntry = *mut libc::c_void;
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;

    unsafe extern "C" {
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> Acl;
        fn acl_get_entry(acl: Acl, entry_id: libc::c_int, entry: *mut AclEntry) -> libc::c_int;
    }

    // SAFETY: `file` supplies a valid descriptor for the duration of call.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(false);
        }
        return Err(error);
    }
    let mut entry: AclEntry = std::ptr::null_mut();
    // SAFETY: `acl` is live and `entry` points to writable storage.
    let get_result = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) };
    let get_error = (get_result < 0).then(io::Error::last_os_error);
    // SAFETY: `acl` came from `acl_get_fd_np` and has not yet been freed.
    let free_result = unsafe { acl_free(acl) };
    if let Some(error) = get_error {
        if error.raw_os_error() == Some(libc::EINVAL) {
            return Ok(false);
        }
        return Err(error);
    }
    if free_result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(get_result == 0)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PeerCredentials {
    pid: u32,
    uid: u32,
}

fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and does not dereference memory.
    unsafe { libc::geteuid() }
}

#[cfg(target_os = "linux")]
fn peer_credentials_impl(fd: RawFd) -> io::Result<PeerCredentials> {
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
    let pid = u32::try_from(cred.pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "socket peer PID is negative"))?;
    Ok(PeerCredentials { pid, uid: cred.uid })
}

#[cfg(target_os = "macos")]
fn peer_credentials_impl(fd: RawFd) -> io::Result<PeerCredentials> {
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

    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: pointers reference initialized uid/gid storage for this call.
    let ret = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    let pid = u32::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "socket peer PID is negative"))?;
    Ok(PeerCredentials { pid, uid })
}

fn peer_pid_impl(fd: RawFd) -> io::Result<Option<u32>> {
    peer_credentials_impl(fd).map(|credentials| Some(credentials.pid))
}

#[cfg(target_os = "linux")]
fn peer_executable_path(pid: u32) -> io::Result<PathBuf> {
    std::fs::canonicalize(PathBuf::from("/proc").join(pid.to_string()).join("exe"))
}

#[cfg(target_os = "macos")]
fn peer_executable_path(pid: u32) -> io::Result<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStringExt;

    let mut buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: buffer is valid for `buffer.len()` bytes and remains alive for
    // the call. `proc_pidpath` writes a NUL-terminated path on success.
    let result = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    if result <= 0 {
        return Err(io::Error::last_os_error());
    }
    let path = CStr::from_bytes_until_nul(&buffer).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "peer path was not NUL-terminated",
        )
    })?;
    std::fs::canonicalize(PathBuf::from(std::ffi::OsString::from_vec(
        path.to_bytes().to_vec(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn bind_creates_parent_dir_and_mode_0600() {
        let dir = std::env::temp_dir().join(format!("sloosh-unix-test-{}", std::process::id()));
        let sock = dir.join("nested").join("sloosh.sock");
        let outcome = bind(&sock).expect("bind should succeed");
        let BindOutcome::Bound(listener) = outcome else {
            panic!("expected Bound, got AlreadyRunning");
        };
        let parent_meta = std::fs::metadata(sock.parent().expect("socket parent"))
            .expect("socket parent should exist");
        let meta = std::fs::metadata(&sock).expect("socket file should exist");
        assert_eq!(parent_meta.permissions().mode() & 0o777, 0o700);
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

    #[tokio::test]
    async fn raw_frames_round_trip_after_json_without_total_limit() {
        let dir =
            std::env::temp_dir().join(format!("sloosh-raw-frame-roundtrip-{}", std::process::id()));
        let sock = dir.join("sloosh.sock");
        let BindOutcome::Bound(listener) = bind(&sock).expect("bind") else {
            panic!("expected Bound")
        };

        let server = tokio::spawn(async move {
            let mut chan = listener.accept().await.expect("accept");
            let req: crate::proto::Request = chan.recv().await.expect("recv JSON").expect("some");
            assert_eq!(req, crate::proto::Request::Status);

            for expected_byte in [0x41, 0x42] {
                let frame = chan
                    .recv_raw_frame()
                    .await
                    .expect("recv frame")
                    .expect("data frame");
                assert_eq!(frame.len(), MAX_RAW_FRAME_BYTES);
                assert!(frame.iter().all(|byte| *byte == expected_byte));
            }
            assert_eq!(chan.recv_raw_frame().await.expect("recv EOF"), None);

            chan.send(&crate::proto::Response::Ok)
                .await
                .expect("send JSON");
            chan.send_raw_frame(b"binary\0reply")
                .await
                .expect("send reply frame");
            chan.send_raw_frame(&[]).await.expect("send EOF");
        });

        let mut client = UnixChannel::connect_unverified(&sock)
            .await
            .expect("connect");
        client
            .send(&crate::proto::Request::Status)
            .await
            .expect("send JSON");
        client
            .send_raw_frame(&vec![0x41; MAX_RAW_FRAME_BYTES])
            .await
            .expect("send first frame");
        client
            .send_raw_frame(&vec![0x42; MAX_RAW_FRAME_BYTES])
            .await
            .expect("send second frame");
        client.send_raw_frame(&[]).await.expect("send EOF");

        let response: crate::proto::Response =
            client.recv().await.expect("recv JSON").expect("some");
        assert_eq!(response, crate::proto::Response::Ok);
        assert_eq!(
            client.recv_raw_frame().await.expect("recv reply"),
            Some(b"binary\0reply".to_vec())
        );
        assert_eq!(client.recv_raw_frame().await.expect("recv EOF"), None);

        server.await.expect("server task");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn json_to_raw_transition_preserves_prefetched_frame_bytes() {
        let dir =
            std::env::temp_dir().join(format!("sloosh-raw-frame-prefetch-{}", std::process::id()));
        let sock = dir.join("sloosh.sock");
        let BindOutcome::Bound(listener) = bind(&sock).expect("bind") else {
            panic!("expected Bound")
        };
        let server = tokio::spawn(async move {
            let mut chan = listener.accept().await.expect("accept");
            let req: crate::proto::Request = chan.recv().await.expect("recv JSON").expect("some");
            assert_eq!(req, crate::proto::Request::Status);
            assert_eq!(
                chan.recv_raw_frame().await.expect("recv frame"),
                Some(b"prefetched bytes".to_vec())
            );
            assert_eq!(chan.recv_raw_frame().await.expect("recv EOF"), None);
        });

        let mut client = UnixChannel::connect_unverified(&sock)
            .await
            .expect("connect");
        let payload = b"prefetched bytes";
        let mut wire = serde_json::to_vec(&crate::proto::Request::Status).expect("serialize JSON");
        wire.push(b'\n');
        wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        wire.extend_from_slice(payload);
        wire.extend_from_slice(&0_u32.to_be_bytes());
        client
            .writer
            .write_all(&wire)
            .await
            .expect("write coalesced JSON and raw frames");

        server.await.expect("server task");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn raw_frames_reject_oversized_send_and_receive() {
        let dir =
            std::env::temp_dir().join(format!("sloosh-raw-frame-oversized-{}", std::process::id()));
        let sock = dir.join("sloosh.sock");
        let BindOutcome::Bound(listener) = bind(&sock).expect("bind") else {
            panic!("expected Bound")
        };
        let server = tokio::spawn(async move { listener.accept().await.expect("accept") });
        let mut client = UnixChannel::connect_unverified(&sock)
            .await
            .expect("connect");
        let mut server = server.await.expect("server task");

        let error = client
            .send_raw_frame(&vec![0_u8; MAX_RAW_FRAME_BYTES + 1])
            .await
            .expect_err("oversized outgoing frame must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let declared_length = u32::try_from(MAX_RAW_FRAME_BYTES + 1).expect("length fits u32");
        client
            .writer
            .write_all(&declared_length.to_be_bytes())
            .await
            .expect("write oversized header");
        let error = server
            .recv_raw_frame()
            .await
            .expect_err("oversized incoming frame must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        drop(client);
        drop(server);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ensure_private_dir_repairs_existing_mode() {
        let dir =
            std::env::temp_dir().join(format!("sloosh-private-dir-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create test dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("set permissive mode");
        #[cfg(target_os = "macos")]
        {
            add_everyone_read_acl(&dir);
            let directory = File::open(&dir).expect("open ACL test directory");
            assert!(
                has_extended_acl_for_test(&directory).expect("read directory ACL"),
                "test setup should add an extended ACL"
            );
        }

        ensure_private_dir(&dir).expect("repair private dir");

        let mode = std::fs::metadata(&dir)
            .expect("private dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
        #[cfg(target_os = "macos")]
        {
            let directory = File::open(&dir).expect("open repaired directory");
            assert!(
                !has_extended_acl_for_test(&directory).expect("read repaired directory ACL"),
                "private directory must not retain an extended ACL"
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn verified_connect_rejects_wrong_expected_uid() {
        let dir = std::env::temp_dir().join(format!("sloosh-peer-uid-test-{}", std::process::id()));
        let sock = dir.join("sloosh.sock");
        let BindOutcome::Bound(listener) = bind(&sock).expect("bind") else {
            panic!("expected Bound")
        };
        let server = tokio::spawn(async move { listener.accept().await.expect("accept") });
        let client = UnixChannel::connect_unverified(&sock)
            .await
            .expect("raw connect");
        let wrong_uid = effective_uid().wrapping_add(1);
        let expected_exe = std::fs::canonicalize(std::env::current_exe().expect("current exe"))
            .expect("canonical current exe");

        let error = client
            .verify_peer_identity_against(wrong_uid, &expected_exe)
            .expect_err("wrong uid must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        drop(server.await.expect("server task"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn verified_connect_rejects_wrong_expected_executable() {
        let dir = std::env::temp_dir().join(format!("sloosh-peer-exe-test-{}", std::process::id()));
        let sock = dir.join("sloosh.sock");
        let BindOutcome::Bound(listener) = bind(&sock).expect("bind") else {
            panic!("expected Bound")
        };
        let server = tokio::spawn(async move { listener.accept().await.expect("accept") });
        let client = UnixChannel::connect_unverified(&sock)
            .await
            .expect("raw connect");

        let error = client
            .verify_peer_identity_against(effective_uid(), Path::new("/not/the/sloosh/executable"))
            .expect_err("wrong executable must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        drop(server.await.expect("server task"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_fallback_socket_is_scoped_to_uid() {
        assert_eq!(
            linux_fallback_socket_path(1234),
            PathBuf::from("/tmp/sloosh-1234/sloosh.sock")
        );
    }
}
