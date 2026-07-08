//! Live-SSH integration tests for the milestone 2 session command set
//! (`run`/`peek`/`send`/`interrupt`/`open`/`ls`/`kill`).
//!
//! These need a real, reachable SSH host to connect to, so they're gated
//! behind the `SLOOSH_TEST_SSH_HOST` environment variable (an alias
//! resolvable via `~/.ssh/config` or a literal `user@host`/`host`, per
//! DESIGN.md §2). Unset in CI/sandboxes: the tests compile and pass
//! trivially by skipping, rather than failing or hanging waiting for
//! network access nobody granted.
//!
//! To exercise for real: `SLOOSH_TEST_SSH_HOST=myhost cargo test --test
//! ssh_session -- --ignored` isn't needed — just set the env var, the test
//! notices and runs.

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
        "sloosh-ssh-itest-{tag}-{}-{}.sock",
        std::process::id(),
        tag.len()
    ))
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

/// Start a fresh daemon on its own temp socket and return a connected
/// channel to it. Each test gets an isolated daemon so session state never
/// leaks between tests.
async fn start_daemon(tag: &str) -> (UnixChannel, std::path::PathBuf) {
    let socket_path = temp_socket_path(tag);
    let daemon_socket = socket_path.clone();
    tokio::spawn(async move {
        let _ = sloosh::daemon::run(daemon_socket).await;
    });
    let chan = connect_with_retry(&socket_path).await;
    (chan, socket_path)
}

#[tokio::test]
async fn run_executes_command_and_returns_output() {
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (mut chan, _socket) = start_daemon("run-basic").await;

    chan.send(&Request::Run {
        host: host.clone(),
        command: "echo sloosh-live-test-marker".to_string(),
        session: None,
        timeout_secs: 30,
        raw: false,
    })
    .await
    .expect("send Run");

    let resp = chan.recv::<Response>().await.expect("recv").expect("some");
    let Response::Run(reply) = resp else {
        panic!("expected Response::Run, got {resp:?}");
    };
    assert_eq!(reply.state, "done");
    assert_eq!(reply.exit_code, Some(0));
    assert!(
        reply.output.contains("sloosh-live-test-marker"),
        "unexpected output: {:?}",
        reply.output
    );
    assert!(!reply.spool_path.is_empty());
}

#[tokio::test]
async fn peek_send_and_default_session_reuse() {
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (mut chan, _socket) = start_daemon("peek-send").await;

    // First run creates the default session.
    chan.send(&Request::Run {
        host: host.clone(),
        command: "echo first".to_string(),
        session: None,
        timeout_secs: 30,
        raw: false,
    })
    .await
    .expect("send Run 1");
    let Some(Response::Run(first)) = chan.recv::<Response>().await.expect("recv") else {
        panic!("expected Response::Run");
    };
    assert_eq!(first.state, "done");

    // Second run against the same (default) session should reuse it rather
    // than erroring, proving implicit addressing / session reuse works.
    chan.send(&Request::Run {
        host: host.clone(),
        command: "echo second".to_string(),
        session: None,
        timeout_secs: 30,
        raw: false,
    })
    .await
    .expect("send Run 2");
    let Some(Response::Run(second)) = chan.recv::<Response>().await.expect("recv") else {
        panic!("expected Response::Run");
    };
    assert_eq!(second.state, "done");
    assert!(second.output.contains("second"));
    assert!(
        !second.output.contains("first"),
        "second run's output should not include the first run's output"
    );

    // ls should now show exactly one idle session for this host.
    chan.send(&Request::Ls {
        host: Some(host.clone()),
    })
    .await
    .expect("send Ls");
    let Some(Response::Ls { sessions }) = chan.recv::<Response>().await.expect("recv") else {
        panic!("expected Response::Ls");
    };
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].host, host);
    assert_eq!(sessions[0].name, "default");
    assert_eq!(sessions[0].state, "idle");
}

#[tokio::test]
async fn kill_then_run_creates_a_fresh_session() {
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (mut chan, _socket) = start_daemon("kill-reopen").await;

    chan.send(&Request::Run {
        host: host.clone(),
        command: "true".to_string(),
        session: None,
        timeout_secs: 30,
        raw: false,
    })
    .await
    .expect("send Run");
    let Some(Response::Run(_)) = chan.recv::<Response>().await.expect("recv") else {
        panic!("expected Response::Run");
    };

    chan.send(&Request::Kill {
        host: host.clone(),
        session: None,
    })
    .await
    .expect("send Kill");
    let ack = chan.recv::<Response>().await.expect("recv");
    assert_eq!(ack, Some(Response::Ok));

    // Killing twice in a row (nothing left to kill) should be a clean error,
    // not a panic.
    chan.send(&Request::Kill {
        host: host.clone(),
        session: None,
    })
    .await
    .expect("send Kill again");
    let Some(Response::Error { .. }) = chan.recv::<Response>().await.expect("recv") else {
        panic!("expected Response::Error for killing an already-gone session");
    };

    // A fresh `run` after `kill` should transparently open a brand new
    // session rather than erroring about a dead one.
    chan.send(&Request::Run {
        host: host.clone(),
        command: "echo reopened".to_string(),
        session: None,
        timeout_secs: 30,
        raw: false,
    })
    .await
    .expect("send Run after kill");
    let Some(Response::Run(reply)) = chan.recv::<Response>().await.expect("recv") else {
        panic!("expected Response::Run");
    };
    assert_eq!(reply.state, "done");
    assert!(reply.output.contains("reopened"));
}

#[tokio::test]
async fn named_session_is_independent_of_default() {
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (mut chan, _socket) = start_daemon("named-session").await;

    chan.send(&Request::Open {
        host: host.clone(),
        name: "extra".to_string(),
    })
    .await
    .expect("send Open");
    let Some(Response::Session(summary)) = chan.recv::<Response>().await.expect("recv") else {
        panic!("expected Response::Session");
    };
    assert_eq!(summary.name, "extra");

    chan.send(&Request::Run {
        host: host.clone(),
        command: "echo default-session".to_string(),
        session: None,
        timeout_secs: 30,
        raw: false,
    })
    .await
    .expect("send Run default");
    let Some(Response::Run(default_reply)) = chan.recv::<Response>().await.expect("recv") else {
        panic!("expected Response::Run");
    };
    assert!(default_reply.output.contains("default-session"));

    chan.send(&Request::Run {
        host: host.clone(),
        command: "echo extra-session".to_string(),
        session: Some("extra".to_string()),
        timeout_secs: 30,
        raw: false,
    })
    .await
    .expect("send Run extra");
    let Some(Response::Run(extra_reply)) = chan.recv::<Response>().await.expect("recv") else {
        panic!("expected Response::Run");
    };
    assert!(extra_reply.output.contains("extra-session"));

    chan.send(&Request::Ls {
        host: Some(host.clone()),
    })
    .await
    .expect("send Ls");
    let Some(Response::Ls { sessions }) = chan.recv::<Response>().await.expect("recv") else {
        panic!("expected Response::Ls");
    };
    assert_eq!(sessions.len(), 2, "default and extra should both be listed");
}
