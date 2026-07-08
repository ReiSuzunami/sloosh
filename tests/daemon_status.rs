//! Integration test: start the daemon against a temp socket path, connect
//! as a client, send `Status`, check the reply — end-to-end proof the
//! accept loop and NDJSON framing work together (DESIGN.md §8 milestone 1).
//!
//! The socket path is overridable via `SLOOSH_SOCKET` (checked here through
//! `transport::unix::resolve_socket_path`, same code path the real CLI
//! uses) specifically so tests don't collide with a real user's daemon.

use sloosh::proto::{Request, Response};
use sloosh::transport::Channel;
use sloosh::transport::unix::UnixChannel;

fn temp_socket_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "sloosh-itest-{tag}-{}-{}.sock",
        std::process::id(),
        tag.len() // trivial extra entropy so parallel calls with the same tag still differ
    ))
}

#[tokio::test]
async fn status_round_trip_against_running_daemon() {
    let socket_path = temp_socket_path("status");
    // SAFETY: this test process does not read SLOOSH_SOCKET concurrently
    // from another thread in a way that would race with this write.
    unsafe {
        std::env::set_var("SLOOSH_SOCKET", &socket_path);
    }
    assert_eq!(
        sloosh::transport::unix::resolve_socket_path(),
        socket_path,
        "resolve_socket_path should honor SLOOSH_SOCKET"
    );

    let daemon_socket = socket_path.clone();
    let daemon = tokio::spawn(async move { sloosh::daemon::run(daemon_socket).await });

    // The daemon binds asynchronously; poll until the socket is connectable.
    let mut chan = connect_with_retry(&socket_path).await;

    chan.send(&Request::Status).await.expect("send Status");
    let reply = match chan.recv::<Response>().await.expect("recv") {
        Some(Response::Status(reply)) => reply,
        other => panic!("expected Response::Status, got {other:?}"),
    };

    assert_eq!(reply.pid, std::process::id());
    assert_eq!(reply.version, env!("CARGO_PKG_VERSION"));
    assert!(reply.sessions.is_empty());
    assert!(reply.leases.is_empty());

    // Ask the daemon to shut down and make sure its task actually exits.
    chan.send(&Request::Shutdown).await.expect("send Shutdown");
    let ack = chan.recv::<Response>().await.expect("recv ack");
    assert_eq!(ack, Some(Response::Ok));

    tokio::time::timeout(std::time::Duration::from_secs(5), daemon)
        .await
        .expect("daemon task should exit after Shutdown")
        .expect("daemon task should not panic")
        .expect("daemon::run should return Ok");

    assert!(
        !socket_path.exists(),
        "daemon should clean up its socket file on shutdown"
    );
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
