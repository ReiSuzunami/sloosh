//! Live-SSH integration tests for the milestone 2/3 session command set
//! (`run`/`peek`/`send`/`interrupt`/`open`/`ls`/`kill`), now gated behind an
//! active lease (docs/internals/architecture.md) same as any other caller.
//!
//! These need a real, reachable SSH host to connect to, so they're gated
//! behind the `SLOOSH_TEST_SSH_HOST` environment variable (an alias
//! resolvable via `~/.ssh/config` or a literal `user@host`/`host`, per
//! docs/internals/architecture.md). Unset in CI/sandboxes: the tests compile and pass
//! trivially by skipping, rather than failing or hanging waiting for
//! network access nobody granted.
//!
//! To exercise for real: `SLOOSH_TEST_SSH_HOST=myhost cargo test --test
//! ssh_session -- --test-threads=1` — single-threaded because each test
//! points `$SLOOSH_HOME` (and thus the vault) at its own temp directory via
//! a process-global env var, so it can't ever touch the real developer's
//! `~/.sloosh/vault`; that isolation only holds with one test running at a
//! time.

use sloosh::daemon::{lease, vault};
use sloosh::proto::{Request, Response, WIRE_PROTOCOL_VERSION};
use sloosh::transport::Channel;
use sloosh::transport::unix::UnixChannel;

fn test_host() -> Option<String> {
    std::env::var("SLOOSH_TEST_SSH_HOST")
        .ok()
        .filter(|s| !s.is_empty())
}

fn temp_socket_path(tag: &str) -> std::path::PathBuf {
    #[cfg(windows)]
    return std::path::PathBuf::from(format!(
        r"\\.\pipe\sloosh-ssh-itest-{tag}-{}-{}",
        std::process::id(),
        tag.len()
    ));

    #[cfg(unix)]
    {
        let dir = std::env::temp_dir().join(format!(
            "sloosh-ssh-itest-{tag}-{}-{}",
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
}

/// Point `$SLOOSH_HOME` at a private temp directory for the rest of this
/// process, so the lease/vault machinery `start_daemon`+`grant_lease_for_test`
/// exercise below never touches the real developer's `~/.sloosh/vault`.
fn set_test_home(tag: &str) -> std::path::PathBuf {
    let home = std::env::temp_dir().join(format!(
        "sloosh-ssh-itest-home-{tag}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&home).expect("create test SLOOSH_HOME");
    // SAFETY: `$SLOOSH_HOME` is process-global, but these live-SSH tests are
    // only ever run manually (gated behind `SLOOSH_TEST_SSH_HOST`) and the
    // module doc comment above tells the operator to use
    // `--test-threads=1` in that case, so no other thread is concurrently
    // reading/writing the environment.
    unsafe {
        std::env::set_var("SLOOSH_HOME", &home);
    }
    home
}

/// Grant this test process itself a lease for `host` (docs/internals/architecture.md), calling
/// the lease/vault machinery directly in-process rather than going through
/// `sloosh request`/`sloosh approve` — this test binary *is* the caller
/// whose ancestry the daemon will check, so `std::process::id()` is the
/// right anchor to request against. The vault is created first (approval
/// never creates it), and approval goes through `approve_lease_for_chain`
/// with an empty approver chain: the daemon-side self-approval guard would
/// (correctly) reject the real `approve_lease` here, since the approver and
/// the requester are the same process.
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

/// Start a fresh daemon on its own temp socket and return a connected
/// channel to it, having already granted this test process a lease for
/// `host` (docs/internals/architecture.md) so the session commands below aren't refused.
/// Each test gets an isolated daemon (and, via `set_test_home`, an isolated
/// vault) so state never leaks between tests.
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
async fn run_executes_command_and_returns_output() {
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (mut chan, _socket) = start_daemon("run-basic", &host).await;

    chan.send(&Request::Run {
        host: host.clone(),
        command: "echo sloosh-live-test-marker".to_string(),
        session: None,
        timeout_secs: 30,
        raw: false,
        lease_token: None,
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
    let (mut chan, _socket) = start_daemon("peek-send", &host).await;

    // First run creates the default session.
    chan.send(&Request::Run {
        host: host.clone(),
        command: "echo first".to_string(),
        session: None,
        timeout_secs: 30,
        raw: false,
        lease_token: None,
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
        lease_token: None,
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
    let (mut chan, _socket) = start_daemon("kill-reopen", &host).await;

    chan.send(&Request::Run {
        host: host.clone(),
        command: "true".to_string(),
        session: None,
        timeout_secs: 30,
        raw: false,
        lease_token: None,
    })
    .await
    .expect("send Run");
    let Some(Response::Run(_)) = chan.recv::<Response>().await.expect("recv") else {
        panic!("expected Response::Run");
    };

    chan.send(&Request::Kill {
        host: host.clone(),
        session: None,
        lease_token: None,
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
        lease_token: None,
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
        lease_token: None,
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
    let (mut chan, _socket) = start_daemon("named-session", &host).await;

    chan.send(&Request::Open {
        host: host.clone(),
        name: "extra".to_string(),
        lease_token: None,
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
        lease_token: None,
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
        lease_token: None,
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
