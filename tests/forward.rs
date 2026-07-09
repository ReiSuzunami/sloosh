//! Live-SSH integration test for `-L` port forwarding (DESIGN.md §6), gated
//! behind `SLOOSH_TEST_SSH_HOST` exactly like `tests/ssh_session.rs` — see
//! that file's module doc for the full rationale and the `--test-threads=1`
//! requirement (each test points `$SLOOSH_HOME` at its own temp dir via a
//! process-global env var).
//!
//! Targets the test host's own sshd (`127.0.0.1:22` from the far end's point
//! of view) rather than standing up a second listener somewhere: any
//! reachable SSH host already has *something* listening on 22, and its
//! banner (`SSH-2.0...`) is a clean, host-agnostic way to prove bytes made
//! it through the tunnel without needing any other service to exist.

use sloosh::daemon::{lease, vault};
use sloosh::proto::{ForwardDirection, Request, Response};
use sloosh::transport::Channel;
use sloosh::transport::unix::UnixChannel;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

fn test_host() -> Option<String> {
    std::env::var("SLOOSH_TEST_SSH_HOST")
        .ok()
        .filter(|s| !s.is_empty())
}

fn temp_socket_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "sloosh-fwd-itest-{tag}-{}-{}.sock",
        std::process::id(),
        tag.len()
    ))
}

/// Point `$SLOOSH_HOME` at a private temp directory for the rest of this
/// process (mirrors `tests/ssh_session.rs::set_test_home`).
fn set_test_home(tag: &str) -> std::path::PathBuf {
    let home = std::env::temp_dir().join(format!(
        "sloosh-fwd-itest-home-{tag}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&home).expect("create test SLOOSH_HOME");
    // SAFETY: see tests/ssh_session.rs's set_test_home — these live-SSH
    // tests are only ever run manually (gated behind SLOOSH_TEST_SSH_HOST)
    // with --test-threads=1, so no other thread is concurrently touching
    // the environment.
    unsafe {
        std::env::set_var("SLOOSH_HOME", &home);
    }
    home
}

/// Grant this test process itself a lease for `host` (DESIGN.md §4), same
/// approach as `tests/ssh_session.rs::grant_lease_for_test`.
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

#[tokio::test]
async fn local_forward_tunnels_to_remote_sshd_and_stops_cleanly() {
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (mut chan, _socket) = start_daemon("local-forward", &host).await;

    chan.send(&Request::Forward {
        host: host.clone(),
        direction: ForwardDirection::Local {
            spec: "0:127.0.0.1:22".to_string(),
        },
        lease_token: None,
    })
    .await
    .expect("send Forward");
    let Some(Response::Forward(opened)) = chan.recv::<Response>().await.expect("recv") else {
        panic!("expected Response::Forward");
    };
    assert!(opened.id.starts_with("fwd-"));
    assert_eq!(opened.host, host);
    assert_eq!(opened.direction, "L");

    // Connect to the forward's local listener and read the far end's sshd
    // banner through the tunnel.
    let mut tcp = TcpStream::connect(opened.listen_addr.as_str())
        .await
        .unwrap_or_else(|e| panic!("connect to forward listener {}: {e}", opened.listen_addr));
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(10), tcp.read(&mut buf))
        .await
        .expect("banner read timed out")
        .expect("banner read failed");
    let banner = String::from_utf8_lossy(&buf[..n]);
    assert!(
        banner.starts_with("SSH-2.0"),
        "unexpected banner: {banner:?}"
    );
    drop(tcp);

    chan.send(&Request::ForwardLs)
        .await
        .expect("send ForwardLs");
    let Some(Response::ForwardLs { forwards }) = chan.recv::<Response>().await.expect("recv")
    else {
        panic!("expected Response::ForwardLs");
    };
    assert_eq!(forwards.len(), 1);
    assert_eq!(forwards[0].id, opened.id);
    assert_eq!(forwards[0].host, host);

    chan.send(&Request::ForwardStop {
        id: opened.id.clone(),
    })
    .await
    .expect("send ForwardStop");
    let ack = chan.recv::<Response>().await.expect("recv");
    assert_eq!(ack, Some(Response::Ok));

    // The listener should be gone: fresh connect attempts must start
    // failing (retry briefly — teardown happens asynchronously relative to
    // the `Ok` ack, which is sent as soon as the stop request is recorded,
    // not once the owner task has actually dropped the listener).
    let listen_addr = opened.listen_addr.clone();
    let mut closed = false;
    for _ in 0..50 {
        if TcpStream::connect(listen_addr.as_str()).await.is_err() {
            closed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        closed,
        "forward's local listener should be closed after stop"
    );

    // Stopping an already-gone forward is a teaching error, not a panic.
    chan.send(&Request::ForwardStop { id: opened.id })
        .await
        .expect("send ForwardStop again");
    let Some(Response::Error { message }) = chan.recv::<Response>().await.expect("recv") else {
        panic!("expected Response::Error for stopping an already-gone forward");
    };
    assert!(message.contains("forward ls"));
}
