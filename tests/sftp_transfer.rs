//! Live-SSH integration tests for `put`/`get` over SFTP (DESIGN.md §5-6).
//!
//! Same gating and isolation story as `tests/ssh_session.rs`: these need a
//! real, reachable SSH host, so they're gated behind `SLOOSH_TEST_SSH_HOST`
//! and skip cleanly (pass trivially) when it's unset. To exercise for real:
//! `SLOOSH_TEST_SSH_HOST=myhost cargo test --test sftp_transfer --
//! --test-threads=1` (single-threaded for the same `$SLOOSH_HOME`-isolation
//! reason as the other live-SSH test file).
//!
//! The remote side of each test writes under `/tmp` and cleans up after
//! itself via a `run` cleanup command — these tests must never depend on or
//! disturb anything else on the target host.

use sloosh::daemon::{lease, vault};
use sloosh::proto::{Request, Response};
use sloosh::transport::Channel;
use sloosh::transport::unix::UnixChannel;

fn test_host() -> Option<String> {
    std::env::var("SLOOSH_TEST_SSH_HOST")
        .ok()
        .filter(|s| !s.is_empty())
}

fn temp_socket_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "sloosh-sftp-itest-{tag}-{}-{}.sock",
        std::process::id(),
        tag.len()
    ))
}

fn set_test_home(tag: &str) -> std::path::PathBuf {
    let home = std::env::temp_dir().join(format!(
        "sloosh-sftp-itest-home-{tag}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&home).expect("create test SLOOSH_HOME");
    // SAFETY: see tests/ssh_session.rs — same single-process, gated,
    // manually-run-only justification for mutating process-global env.
    unsafe {
        std::env::set_var("SLOOSH_HOME", &home);
    }
    home
}

async fn grant_lease_for_test(host: &str) {
    if !vault::exists() {
        vault::create(
            &vault::VaultData::default(),
            b"sloosh-live-test-master-password",
        )
        .expect("create test vault");
    }
    let pid = std::process::id();
    match lease::request_lease(pid, vec![host.to_string()])
        .await
        .expect("request test lease")
    {
        lease::RequestOutcome::AlreadyAuthorized => {}
        lease::RequestOutcome::Pending(info) => {
            lease::approve_lease_for_chain(&[], &info.id, b"sloosh-live-test-master-password")
                .await
                .expect("approve test lease");
        }
    }
}

async fn connect_with_retry(path: &std::path::Path) -> UnixChannel {
    let mut delay = std::time::Duration::from_millis(10);
    for _ in 0..50 {
        if let Ok(chan) = UnixChannel::connect(path).await {
            return chan;
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(std::time::Duration::from_millis(200));
    }
    panic!("daemon never became connectable at {}", path.display());
}

async fn start_daemon(tag: &str, host: &str) -> (UnixChannel, std::path::PathBuf) {
    set_test_home(tag);
    grant_lease_for_test(host).await;
    let socket_path = temp_socket_path(tag);
    let daemon_socket = socket_path.clone();
    tokio::spawn(async move {
        let _ = sloosh::daemon::run(daemon_socket).await;
    });
    let chan = connect_with_retry(&socket_path).await;
    (chan, socket_path)
}

/// A local temp file with `contents` written to it, cleaned up on drop.
struct LocalTempFile {
    path: std::path::PathBuf,
}

impl LocalTempFile {
    fn new(tag: &str, contents: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "sloosh-sftp-itest-local-{tag}-{}-{}",
            std::process::id(),
            tag.len()
        ));
        std::fs::write(&path, contents).expect("write local temp file");
        Self { path }
    }

    fn path_str(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

impl Drop for LocalTempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A local temp path that does not exist yet (a `get` destination),
/// removed on drop if it ends up created.
struct LocalTempSlot {
    path: std::path::PathBuf,
}

impl LocalTempSlot {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "sloosh-sftp-itest-slot-{tag}-{}-{}",
            std::process::id(),
            tag.len()
        ));
        let _ = std::fs::remove_file(&path);
        Self { path }
    }

    fn path_str(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

impl Drop for LocalTempSlot {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Ask the remote host to remove `path`, ignoring failures — best-effort
/// cleanup so a failed assertion earlier in a test doesn't leave litter on
/// the target host.
async fn remote_rm(chan: &mut UnixChannel, host: &str, path: &str) {
    let _ = chan
        .send(&Request::Run {
            host: host.to_string(),
            command: format!("rm -f {path}"),
            session: None,
            timeout_secs: 15,
            raw: false,
            lease_token: None,
        })
        .await;
    let _: Result<Option<Response>, _> = chan.recv().await;
}

#[tokio::test]
async fn put_then_get_round_trips_file_content() {
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (mut chan, _socket) = start_daemon("put-get-roundtrip", &host).await;

    let payload = b"sloosh sftp round-trip test payload\n".to_vec();
    let local_src = LocalTempFile::new("src", &payload);
    let remote_path = format!("/tmp/sloosh-sftp-itest-{}.txt", std::process::id());

    chan.send(&Request::Put {
        host: host.clone(),
        local_path: local_src.path_str(),
        remote_path: remote_path.clone(),
        session: None,
        lease_token: None,
    })
    .await
    .expect("send Put");
    let resp = chan.recv::<Response>().await.expect("recv").expect("some");
    let Response::Transfer(put_reply) = resp else {
        remote_rm(&mut chan, &host, &remote_path).await;
        panic!("expected Response::Transfer for Put, got {resp:?}");
    };
    assert_eq!(put_reply.bytes_transferred, payload.len() as u64);
    assert_eq!(put_reply.host, host);
    assert_eq!(put_reply.remote_path, remote_path);

    let local_dst = LocalTempSlot::new("dst");
    chan.send(&Request::Get {
        host: host.clone(),
        remote_path: remote_path.clone(),
        local_path: local_dst.path_str(),
        session: None,
        force: false,
        lease_token: None,
    })
    .await
    .expect("send Get");
    let resp = chan.recv::<Response>().await.expect("recv").expect("some");
    let Response::Transfer(get_reply) = resp else {
        remote_rm(&mut chan, &host, &remote_path).await;
        panic!("expected Response::Transfer for Get, got {resp:?}");
    };
    assert_eq!(get_reply.bytes_transferred, payload.len() as u64);

    let downloaded = std::fs::read(&local_dst.path).expect("read downloaded file");
    assert_eq!(downloaded, payload);

    remote_rm(&mut chan, &host, &remote_path).await;
}

#[tokio::test]
async fn get_refuses_to_overwrite_existing_local_file_without_force() {
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (mut chan, _socket) = start_daemon("get-no-overwrite", &host).await;

    let remote_path = format!("/tmp/sloosh-sftp-itest-noforce-{}.txt", std::process::id());
    // Bound to a variable: an unbound temporary would be dropped (deleting
    // the file) at the end of the `send` statement, before the daemon task
    // gets around to reading it.
    let local_src = LocalTempFile::new("noforce-src", b"remote content");
    chan.send(&Request::Put {
        host: host.clone(),
        local_path: local_src.path_str(),
        remote_path: remote_path.clone(),
        session: None,
        lease_token: None,
    })
    .await
    .expect("send Put");
    let resp = chan.recv::<Response>().await.expect("recv");
    let Some(Response::Transfer(_)) = resp else {
        remote_rm(&mut chan, &host, &remote_path).await;
        panic!("expected Response::Transfer for Put, got {resp:?}");
    };

    // The local destination already has content before the Get.
    let local_dst = LocalTempFile::new("noforce-dst", b"pre-existing local content");

    chan.send(&Request::Get {
        host: host.clone(),
        remote_path: remote_path.clone(),
        local_path: local_dst.path_str(),
        session: None,
        force: false,
        lease_token: None,
    })
    .await
    .expect("send Get");
    let resp = chan.recv::<Response>().await.expect("recv").expect("some");
    let Response::Error { message } = &resp else {
        remote_rm(&mut chan, &host, &remote_path).await;
        panic!("expected Response::Error refusing the overwrite, got {resp:?}");
    };
    assert!(
        message.contains("--force"),
        "error should point at --force: {message}"
    );
    // Local file must be untouched.
    let still_there = std::fs::read(&local_dst.path).expect("read local file");
    assert_eq!(still_there, b"pre-existing local content");

    // Retrying with force: true must succeed and overwrite it.
    chan.send(&Request::Get {
        host: host.clone(),
        remote_path: remote_path.clone(),
        local_path: local_dst.path_str(),
        session: None,
        force: true,
        lease_token: None,
    })
    .await
    .expect("send Get with force");
    let resp = chan.recv::<Response>().await.expect("recv").expect("some");
    let Response::Transfer(_) = &resp else {
        remote_rm(&mut chan, &host, &remote_path).await;
        panic!("expected Response::Transfer for forced Get, got {resp:?}");
    };
    let overwritten = std::fs::read(&local_dst.path).expect("read local file");
    assert_eq!(overwritten, b"remote content");

    remote_rm(&mut chan, &host, &remote_path).await;
}

#[tokio::test]
async fn put_missing_local_file_is_a_self_teaching_error() {
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (mut chan, _socket) = start_daemon("put-missing-local", &host).await;

    let missing = std::env::temp_dir().join(format!(
        "sloosh-sftp-itest-does-not-exist-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&missing);

    chan.send(&Request::Put {
        host: host.clone(),
        local_path: missing.to_string_lossy().into_owned(),
        remote_path: "/tmp/sloosh-sftp-itest-should-not-be-created".to_string(),
        session: None,
        lease_token: None,
    })
    .await
    .expect("send Put");
    let resp = chan.recv::<Response>().await.expect("recv").expect("some");
    let Response::Error { message } = &resp else {
        panic!("expected Response::Error for a missing local file, got {resp:?}");
    };
    assert!(
        message.contains("does not exist") || message.contains("not readable"),
        "error should explain the local file is missing: {message}"
    );
}

#[tokio::test]
async fn get_missing_remote_path_is_a_self_teaching_error() {
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (mut chan, _socket) = start_daemon("get-missing-remote", &host).await;

    let local_dst = LocalTempSlot::new("missing-remote-dst");
    chan.send(&Request::Get {
        host: host.clone(),
        remote_path: format!(
            "/tmp/sloosh-sftp-itest-definitely-does-not-exist-{}",
            std::process::id()
        ),
        local_path: local_dst.path_str(),
        session: None,
        force: false,
        lease_token: None,
    })
    .await
    .expect("send Get");
    let resp = chan.recv::<Response>().await.expect("recv").expect("some");
    let Response::Error { message } = &resp else {
        panic!("expected Response::Error for a missing remote path, got {resp:?}");
    };
    assert!(
        message.contains("no such file") || message.contains("permission"),
        "error should explain the remote path problem: {message}"
    );
    assert!(
        !local_dst.path.exists(),
        "a failed Get must not create the local destination"
    );
}
