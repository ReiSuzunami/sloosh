//! Windows named-pipe transport with process identity verification.

use super::{BindOutcome, Channel, MAX_RAW_FRAME_BYTES};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use tokio::sync::Mutex;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorDacl, GetTokenInformation,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("failed to create directory {path}: {source}")]
    CreateDir { path: PathBuf, source: io::Error },
    #[error("failed to bind sloosh named pipe at {path}: {source}")]
    Bind { path: PathBuf, source: io::Error },
    #[error("failed to inspect private directory {path}: {source}")]
    OpenDirectory { path: PathBuf, source: io::Error },
    #[error("refusing to use {path} as a private directory: {reason}")]
    UnsafeDirectory { path: PathBuf, reason: &'static str },
}

pub fn sloosh_home() -> PathBuf {
    if let Some(path) = std::env::var_os("SLOOSH_HOME") {
        return PathBuf::from(path);
    }
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(std::env::temp_dir)
        .join("Sloosh")
}

pub fn daemon_log_path() -> PathBuf {
    sloosh_home().join("daemon.log")
}

pub fn resolve_socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os("SLOOSH_SOCKET") {
        return PathBuf::from(path);
    }
    let mut hash = Sha256::new();
    if let Ok(sid) = current_user_sid_string() {
        hash.update(sid.as_bytes());
        hash.update([0]);
    }
    hash.update(sloosh_home().as_os_str().to_string_lossy().as_bytes());
    let digest = hash.finalize();
    PathBuf::from(format!(
        r"\\.\pipe\sloosh-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]
    ))
}

enum PipeStream {
    Client(NamedPipeClient),
    Server(NamedPipeServer),
}

impl AsyncRead for PipeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Client(pipe) => Pin::new(pipe).poll_read(cx, buf),
            Self::Server(pipe) => Pin::new(pipe).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for PipeStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match &mut *self {
            Self::Client(pipe) => Pin::new(pipe).poll_write(cx, buf),
            Self::Server(pipe) => Pin::new(pipe).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match &mut *self {
            Self::Client(pipe) => Pin::new(pipe).poll_flush(cx),
            Self::Server(pipe) => Pin::new(pipe).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match &mut *self {
            Self::Client(pipe) => Pin::new(pipe).poll_shutdown(cx),
            Self::Server(pipe) => Pin::new(pipe).poll_shutdown(cx),
        }
    }
}

#[derive(Clone, Copy)]
enum PeerSide {
    Client,
    Server,
}

/// Compatibility name used by existing platform-neutral callers.
pub struct UnixChannel {
    reader: BufReader<tokio::io::ReadHalf<PipeStream>>,
    writer: tokio::io::WriteHalf<PipeStream>,
    handle: isize,
    peer_side: PeerSide,
}

impl UnixChannel {
    fn from_stream(stream: PipeStream, peer_side: PeerSide) -> Self {
        let handle = match &stream {
            PipeStream::Client(pipe) => pipe.as_raw_handle() as isize,
            PipeStream::Server(pipe) => pipe.as_raw_handle() as isize,
        };
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: BufReader::new(reader),
            writer,
            handle,
            peer_side,
        }
    }

    pub async fn connect(path: &Path) -> io::Result<Self> {
        let expected_exe = std::env::current_exe()?;
        Self::connect_verified(path, &expected_exe).await
    }

    pub async fn connect_verified(path: &Path, expected_exe: &Path) -> io::Result<Self> {
        let channel = Self::connect_unverified(path).await?;
        channel
            .verify_peer_identity(expected_exe)
            .map_err(|source| {
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

    pub(crate) fn verify_peer_identity(&self, expected_exe: &Path) -> io::Result<()> {
        let pid = self.verified_peer_pid()?;
        let actual = process_executable(pid)?;
        let expected = std::fs::canonicalize(expected_exe)?;
        if !windows_paths_equal(&actual, &expected) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "named-pipe peer executable {} does not match {}",
                    actual.display(),
                    expected.display()
                ),
            ));
        }
        Ok(())
    }

    pub async fn connect_unverified(path: &Path) -> io::Result<Self> {
        let pipe = ClientOptions::new().open(path)?;
        Ok(Self::from_stream(
            PipeStream::Client(pipe),
            PeerSide::Server,
        ))
    }

    fn raw_peer_pid(&self) -> io::Result<u32> {
        let mut pid = 0_u32;
        // SAFETY: `handle` remains owned by the split pipe stream and `pid`
        // points to writable storage for the duration of the call.
        let result = unsafe {
            match self.peer_side {
                PeerSide::Client => {
                    GetNamedPipeClientProcessId(HANDLE(self.handle as *mut _), &mut pid)
                }
                PeerSide::Server => {
                    GetNamedPipeServerProcessId(HANDLE(self.handle as *mut _), &mut pid)
                }
            }
        };
        result.map_err(io::Error::from)?;
        Ok(pid)
    }

    fn verified_peer_pid(&self) -> io::Result<u32> {
        let pid = self.raw_peer_pid()?;
        if !process_has_current_user(pid)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("named-pipe peer pid {pid} belongs to a different Windows user"),
            ));
        }
        Ok(pid)
    }
}

impl Channel for UnixChannel {
    fn peer_pid(&self) -> io::Result<Option<u32>> {
        self.verified_peer_pid().map(Some)
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

pub struct UnixListener {
    path: PathBuf,
    next: Mutex<Option<NamedPipeServer>>,
}

impl UnixListener {
    pub async fn accept(&self) -> io::Result<UnixChannel> {
        let server = self
            .next
            .lock()
            .await
            .take()
            .ok_or_else(|| io::Error::other("named-pipe listener lost its next instance"))?;
        server.connect().await?;
        let next = create_server(&self.path, false)?;
        *self.next.lock().await = Some(next);
        Ok(UnixChannel::from_stream(
            PipeStream::Server(server),
            PeerSide::Client,
        ))
    }
}

pub fn bind(path: &Path) -> Result<BindOutcome<UnixListener>, TransportError> {
    let first = match create_server(path, true) {
        Ok(server) => server,
        Err(_source) if ClientOptions::new().open(path).is_ok() => {
            return Ok(BindOutcome::AlreadyRunning);
        }
        Err(source) => {
            return Err(TransportError::Bind {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    Ok(BindOutcome::Bound(UnixListener {
        path: path.to_path_buf(),
        next: Mutex::new(Some(first)),
    }))
}

fn create_server(path: &Path, first: bool) -> io::Result<NamedPipeServer> {
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true)
        .max_instances(254);
    options.create(path)
}

pub fn ensure_private_dir(path: &Path) -> Result<(), TransportError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path).map_err(|source| TransportError::CreateDir {
                path: path.to_path_buf(),
                source,
            })?;
            std::fs::symlink_metadata(path).map_err(|source| TransportError::OpenDirectory {
                path: path.to_path_buf(),
                source,
            })?
        }
        Err(source) => {
            return Err(TransportError::OpenDirectory {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(TransportError::UnsafeDirectory {
            path: path.to_path_buf(),
            reason: "path is a symlink/reparse point or not a directory",
        });
    }
    secure_directory_acl(path).map_err(|source| TransportError::OpenDirectory {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

pub(crate) fn clear_extended_acl(_file: &std::fs::File) -> io::Result<()> {
    Ok(())
}

fn windows_paths_equal(left: &Path, right: &Path) -> bool {
    let left = left.as_os_str().to_string_lossy();
    let right = right.as_os_str().to_string_lossy();
    left.trim_start_matches(r"\\?\")
        .eq_ignore_ascii_case(right.trim_start_matches(r"\\?\"))
}

fn process_executable(pid: u32) -> io::Result<PathBuf> {
    // SAFETY: the returned process handle is closed below and is used only
    // with query access. The buffer length always matches its allocation.
    unsafe {
        let process =
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(io::Error::from)?;
        let mut buffer = vec![0_u16; 32_768];
        let mut length = buffer.len() as u32;
        let result = QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buffer.as_mut_ptr()),
            &mut length,
        );
        let _ = CloseHandle(process);
        result.map_err(io::Error::from)?;
        buffer.truncate(length as usize);
        Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
    }
}

fn process_has_current_user(pid: u32) -> io::Result<bool> {
    // SAFETY: all handles are closed on every successful open path. Token
    // buffers are sized from GetTokenInformation before pointer access.
    unsafe {
        let peer_process =
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(io::Error::from)?;
        let peer_token = open_query_token(peer_process);
        let _ = CloseHandle(peer_process);
        let peer_token = peer_token?;
        let current_token = open_query_token(GetCurrentProcess())?;
        let peer_sid = token_user_buffer(peer_token);
        let current_sid = token_user_buffer(current_token);
        let _ = CloseHandle(peer_token);
        let _ = CloseHandle(current_token);
        let peer_sid = peer_sid?;
        let current_sid = current_sid?;
        let peer = &*(peer_sid.as_ptr() as *const TOKEN_USER);
        let current = &*(current_sid.as_ptr() as *const TOKEN_USER);
        Ok(EqualSid(peer.User.Sid, current.User.Sid).is_ok())
    }
}

unsafe fn open_query_token(process: HANDLE) -> io::Result<HANDLE> {
    let mut token = HANDLE::default();
    // SAFETY: caller supplies a live process handle and `token` is writable.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.map_err(io::Error::from)?;
    Ok(token)
}

unsafe fn token_user_buffer(token: HANDLE) -> io::Result<Vec<u8>> {
    let mut needed = 0_u32;
    // SAFETY: the first call intentionally queries the required size.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0_u8; needed as usize];
    // SAFETY: buffer has exactly the size requested by Windows.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
    }
    .map_err(io::Error::from)?;
    Ok(buffer)
}

fn secure_directory_acl(path: &Path) -> io::Result<()> {
    let sid = current_user_sid_string()?;
    let sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})");
    let sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: SDDL is NUL-terminated and descriptor is an output pointer
    // freed with LocalFree after SetNamedSecurityInfoW returns.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            windows::core::PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(io::Error::from)?;
    let mut present = windows::core::BOOL::default();
    let mut defaulted = windows::core::BOOL::default();
    let mut dacl = std::ptr::null_mut();
    // SAFETY: descriptor is a valid self-relative security descriptor.
    let dacl_result =
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) };
    if let Err(error) = dacl_result {
        // SAFETY: descriptor was allocated by LocalAlloc via the conversion API.
        unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
        return Err(io::Error::from(error));
    }
    if !present.as_bool() || dacl.is_null() {
        // SAFETY: descriptor was allocated by LocalAlloc via the conversion API.
        unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "generated private directory descriptor has no DACL",
        ));
    }
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: path is NUL-terminated; DACL remains owned by descriptor during call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            windows::core::PWSTR(path.as_ptr().cast_mut()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    // SAFETY: descriptor was allocated by LocalAlloc and the synchronous ACL
    // update no longer borrows its DACL.
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    status.ok().map_err(io::Error::from)
}

fn current_user_sid_string() -> io::Result<String> {
    // SAFETY: current process pseudo-handle is valid and the token is closed.
    unsafe {
        let token = open_query_token(GetCurrentProcess())?;
        let buffer = token_user_buffer(token);
        let _ = CloseHandle(token);
        let buffer = buffer?;
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let mut string = windows::core::PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut string).map_err(io::Error::from)?;
        let value = string
            .to_string()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
        LocalFree(Some(HLOCAL(string.0.cast())));
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Request, Response};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique_pipe(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        PathBuf::from(format!(
            r"\\.\pipe\sloosh-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[tokio::test]
    async fn named_pipe_round_trip_verifies_process_and_framing() {
        let path = unique_pipe("round-trip");
        let listener = match bind(&path).expect("bind named pipe") {
            BindOutcome::Bound(listener) => listener,
            BindOutcome::AlreadyRunning => panic!("unique test pipe is already running"),
        };
        let server = tokio::spawn(async move {
            let mut channel = listener.accept().await.expect("accept client");
            assert_eq!(channel.peer_pid().unwrap(), Some(std::process::id()));
            assert!(matches!(
                channel.recv().await.unwrap(),
                Some(Request::Status)
            ));
            channel.send(&Response::Ok).await.unwrap();
        });
        let mut client = UnixChannel::connect(&path).await.expect("verified connect");
        assert_eq!(client.peer_pid().unwrap(), Some(std::process::id()));
        client.send(&Request::Status).await.unwrap();
        assert_eq!(client.recv::<Response>().await.unwrap(), Some(Response::Ok));
        server.await.unwrap();
    }

    #[test]
    fn executable_comparison_accepts_extended_length_prefix() {
        assert!(windows_paths_equal(
            Path::new(r"C:\Program Files\Sloosh\slooshd.exe"),
            Path::new(r"\\?\C:\Program Files\Sloosh\slooshd.exe")
        ));
    }
}
