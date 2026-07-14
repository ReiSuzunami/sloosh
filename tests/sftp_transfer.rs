//! Live-SSH integration tests for `put`/`get` over SFTP (docs/internals/architecture.md).
//!
//! Same gating and isolation story as `tests/ssh_session.rs`: these need a
//! real, reachable SSH host, so they're gated behind `SLOOSH_TEST_SSH_HOST`
//! and skip cleanly (pass trivially) when it's unset. To exercise for real:
//! `SLOOSH_TEST_SSH_HOST=myhost cargo test --features integration-test-hooks
//! --test sftp_transfer -- --test-threads=1` (single-threaded for the same
//! `$SLOOSH_HOME`-isolation
//! reason as the other live-SSH test file).
//!
//! The remote side of each test writes under `/tmp` and cleans up after
//! itself via a `run` cleanup command — these tests must never depend on or
//! disturb anything else on the target host.

#[cfg(feature = "integration-test-hooks")]
use sloosh::daemon::session;
use sloosh::daemon::{lease, vault};
use sloosh::proto::{Request, Response, TransferReply, WIRE_PROTOCOL_VERSION};
use sloosh::transport::unix::UnixChannel;
use sloosh::transport::{Channel, MAX_RAW_FRAME_BYTES};

fn test_host() -> Option<String> {
    std::env::var("SLOOSH_TEST_SSH_HOST")
        .ok()
        .filter(|s| !s.is_empty())
}

fn temp_socket_path(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sloosh-sftp-itest-{tag}-{}-{}",
        std::process::id(),
        tag.len()
    ));
    std::fs::create_dir_all(&dir).expect("create private socket dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("secure socket dir");
    }
    dir.join("sloosh.sock")
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
        if let Ok(mut chan) = UnixChannel::connect(path).await {
            chan.send(&Request::Hello {
                wire_protocol: WIRE_PROTOCOL_VERSION,
            })
            .await
            .expect("send protocol hello");
            assert_eq!(
                chan.recv::<Response>()
                    .await
                    .expect("receive protocol ready"),
                Some(Response::ProtocolReady {
                    wire_protocol: WIRE_PROTOCOL_VERSION,
                })
            );
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

async fn put_bytes(
    chan: &mut UnixChannel,
    host: &str,
    local_label: &str,
    remote_path: &str,
    bytes: &[u8],
) -> TransferReply {
    chan.send(&Request::Put {
        host: host.to_string(),
        local_path: local_label.to_string(),
        remote_path: remote_path.to_string(),
        session: None,
        lease_token: None,
    })
    .await
    .expect("send Put");
    assert_eq!(
        chan.recv::<Response>().await.unwrap(),
        Some(Response::TransferReady)
    );
    for chunk in bytes.chunks(MAX_RAW_FRAME_BYTES) {
        chan.send_raw_frame(chunk).await.expect("send upload frame");
    }
    chan.send_raw_frame(&[]).await.expect("send upload eof");
    match chan
        .recv::<Response>()
        .await
        .unwrap()
        .expect("final Put reply")
    {
        Response::Transfer(reply) => reply,
        other => panic!("expected Transfer, got {other:?}"),
    }
}

#[tokio::test]
async fn put_then_get_crosses_multiple_raw_frames_without_total_limit() {
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (mut chan, _socket) = start_daemon("put-get-multiframe", &host).await;

    // Cross the rejected design's former 32 MiB whole-transfer ceiling so a
    // future aggregate cap cannot return unnoticed. Only each frame is
    // bounded; the stream itself is not.
    let payload_len = MAX_RAW_FRAME_BYTES * 33 + 257;
    let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
    let remote_path = format!(
        "/tmp/sloosh-sftp-itest-multiframe-{}.bin",
        std::process::id()
    );

    let put_reply = put_bytes(
        &mut chan,
        &host,
        "/virtual/multiframe-source",
        &remote_path,
        &payload,
    )
    .await;
    assert_eq!(put_reply.bytes_transferred, payload_len as u64);

    let (get_reply, downloaded) = get_bytes(
        &mut chan,
        &host,
        &remote_path,
        "/virtual/multiframe-destination",
    )
    .await;
    assert_eq!(get_reply.bytes_transferred, payload_len as u64);
    assert_eq!(downloaded, payload);

    remote_rm(&mut chan, &host, &remote_path).await;
}

#[cfg(feature = "integration-test-hooks")]
#[tokio::test]
async fn in_flight_put_survives_lease_expiry_and_next_transfer_is_denied() {
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (mut chan, _socket) = start_daemon("put-expired-lease", &host).await;
    let remote_path = format!(
        "/tmp/sloosh-sftp-itest-expired-lease-{}.bin",
        std::process::id()
    );
    let first = vec![0x41; MAX_RAW_FRAME_BYTES];
    let second = vec![0x42; MAX_RAW_FRAME_BYTES];

    chan.send(&Request::Put {
        host: host.clone(),
        local_path: "/virtual/lease-expiry-source".to_string(),
        remote_path: remote_path.clone(),
        session: None,
        lease_token: None,
    })
    .await
    .expect("send Put");
    assert_eq!(
        chan.recv::<Response>().await.unwrap(),
        Some(Response::TransferReady)
    );
    chan.send_raw_frame(&first).await.expect("send first frame");

    lease::expire_active_leases_for_integration_test().await;

    chan.send_raw_frame(&second)
        .await
        .expect("send frame after lease expiry");
    chan.send_raw_frame(&[]).await.expect("send upload eof");
    let completed = chan
        .recv::<Response>()
        .await
        .unwrap()
        .expect("final Put reply");
    let Response::Transfer(reply) = completed else {
        panic!("in-flight Put should complete after lease expiry, got {completed:?}");
    };
    assert_eq!(reply.bytes_transferred, (first.len() + second.len()) as u64);

    chan.send(&Request::Get {
        host: host.clone(),
        remote_path: remote_path.clone(),
        local_path: "/virtual/new-transfer".to_string(),
        session: None,
        lease_token: None,
    })
    .await
    .expect("send Get after lease expiry");
    let denied = chan
        .recv::<Response>()
        .await
        .unwrap()
        .expect("lease denial reply");
    let Response::Error { message } = denied else {
        panic!("new transfer should be denied after lease expiry, got {denied:?}");
    };
    assert!(message.contains("lease"), "unexpected denial: {message}");

    grant_lease_for_test(&host).await;
    remote_rm(&mut chan, &host, &remote_path).await;
}

#[cfg(feature = "integration-test-hooks")]
#[tokio::test]
async fn in_flight_get_survives_lease_expiry_and_session_reaping() {
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (mut chan, _socket) = start_daemon("get-expired-lease", &host).await;
    let remote_path = format!(
        "/tmp/sloosh-sftp-itest-get-expired-lease-{}.bin",
        std::process::id()
    );
    let payload_len = MAX_RAW_FRAME_BYTES * 4 + 257;
    let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
    put_bytes(
        &mut chan,
        &host,
        "/virtual/get-expiry-source",
        &remote_path,
        &payload,
    )
    .await;

    chan.send(&Request::Get {
        host: host.clone(),
        remote_path: remote_path.clone(),
        local_path: "/virtual/get-expiry-destination".to_string(),
        session: None,
        lease_token: None,
    })
    .await
    .expect("send Get");
    assert_eq!(
        chan.recv::<Response>().await.unwrap(),
        Some(Response::TransferReady)
    );
    let first = chan
        .recv_raw_frame()
        .await
        .expect("receive first download frame")
        .expect("download must not be empty");
    let mut downloaded = first;

    lease::expire_active_leases_for_integration_test().await;
    session::kill(&host, None)
        .await
        .expect("simulate the PTY idle reaper closing the reused session");

    while let Some(chunk) = chan.recv_raw_frame().await.expect("download frame") {
        downloaded.extend_from_slice(&chunk);
    }
    let completed = chan
        .recv::<Response>()
        .await
        .unwrap()
        .expect("final Get reply");
    let Response::Transfer(reply) = completed else {
        panic!("in-flight Get should survive expiry/reaping, got {completed:?}");
    };
    assert_eq!(reply.bytes_transferred, payload.len() as u64);
    assert_eq!(downloaded, payload);

    chan.send(&Request::Get {
        host: host.clone(),
        remote_path: remote_path.clone(),
        local_path: "/virtual/new-get".to_string(),
        session: None,
        lease_token: None,
    })
    .await
    .expect("send new Get after expiry");
    let denied = chan
        .recv::<Response>()
        .await
        .unwrap()
        .expect("lease denial reply");
    assert!(
        matches!(&denied, Response::Error { message } if message.contains("lease")),
        "new Get should be denied after lease expiry: {denied:?}"
    );

    grant_lease_for_test(&host).await;
    remote_rm(&mut chan, &host, &remote_path).await;
}

async fn get_bytes(
    chan: &mut UnixChannel,
    host: &str,
    remote_path: &str,
    local_label: &str,
) -> (TransferReply, Vec<u8>) {
    chan.send(&Request::Get {
        host: host.to_string(),
        remote_path: remote_path.to_string(),
        local_path: local_label.to_string(),
        session: None,
        lease_token: None,
    })
    .await
    .expect("send Get");
    assert_eq!(
        chan.recv::<Response>().await.unwrap(),
        Some(Response::TransferReady)
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = chan.recv_raw_frame().await.expect("download frame") {
        bytes.extend_from_slice(&chunk);
    }
    let reply = match chan
        .recv::<Response>()
        .await
        .unwrap()
        .expect("final Get reply")
    {
        Response::Transfer(reply) => reply,
        other => panic!("expected Transfer, got {other:?}"),
    };
    (reply, bytes)
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
    let remote_path = format!("/tmp/sloosh-sftp-itest-{}.txt", std::process::id());

    let put_reply = put_bytes(&mut chan, &host, "/virtual/source", &remote_path, &payload).await;
    assert_eq!(put_reply.bytes_transferred, payload.len() as u64);
    assert_eq!(put_reply.host, host);
    assert_eq!(put_reply.remote_path, remote_path);

    let (get_reply, downloaded) =
        get_bytes(&mut chan, &host, &remote_path, "/virtual/destination").await;
    assert_eq!(get_reply.bytes_transferred, payload.len() as u64);
    assert_eq!(downloaded, payload);

    remote_rm(&mut chan, &host, &remote_path).await;
}

#[tokio::test]
async fn get_stream_never_writes_the_local_path_label() {
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (mut chan, _socket) = start_daemon("get-no-overwrite", &host).await;

    let remote_path = format!("/tmp/sloosh-sftp-itest-noforce-{}.txt", std::process::id());
    put_bytes(
        &mut chan,
        &host,
        "/virtual/source",
        &remote_path,
        b"remote content",
    )
    .await;

    let local_dst = std::env::temp_dir().join(format!(
        "sloosh-sftp-itest-local-label-{}",
        std::process::id()
    ));
    std::fs::write(&local_dst, b"pre-existing local content").expect("write local label file");

    let (_reply, downloaded) =
        get_bytes(&mut chan, &host, &remote_path, &local_dst.to_string_lossy()).await;
    assert_eq!(downloaded, b"remote content");
    let still_there = std::fs::read(&local_dst).expect("read local file");
    assert_eq!(still_there, b"pre-existing local content");

    let _ = std::fs::remove_file(&local_dst);
    remote_rm(&mut chan, &host, &remote_path).await;
}

#[tokio::test]
async fn put_treats_local_path_as_label_only() {
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
    let remote_path = format!("/tmp/sloosh-sftp-itest-label-only-{}", std::process::id());

    let reply = put_bytes(
        &mut chan,
        &host,
        &missing.to_string_lossy(),
        &remote_path,
        b"label only",
    )
    .await;
    assert_eq!(reply.bytes_transferred, 10);
    let (_, downloaded) = get_bytes(&mut chan, &host, &remote_path, "/virtual/dst").await;
    assert_eq!(downloaded, b"label only");

    remote_rm(&mut chan, &host, &remote_path).await;
}

#[tokio::test]
async fn get_missing_remote_path_is_a_self_teaching_error() {
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (mut chan, _socket) = start_daemon("get-missing-remote", &host).await;

    let local_dst = std::env::temp_dir().join(format!(
        "sloosh-sftp-itest-missing-remote-dst-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&local_dst);
    chan.send(&Request::Get {
        host: host.clone(),
        remote_path: format!(
            "/tmp/sloosh-sftp-itest-definitely-does-not-exist-{}",
            std::process::id()
        ),
        local_path: local_dst.to_string_lossy().into_owned(),
        session: None,
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
        !local_dst.exists(),
        "a failed Get must not create the local destination"
    );
}
