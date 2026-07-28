//! Live-SSH integration tests for `-L` and `-R` port forwarding, gated
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

use sloosh::daemon::ssh::{self, LeaseContext};
use sloosh::daemon::{lease, vault};
use sloosh::proto::{ForwardDirection, Request, Response, WIRE_PROTOCOL_VERSION};
use sloosh::transport::Channel;
use sloosh::transport::unix::UnixChannel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn test_host() -> Option<String> {
    std::env::var("SLOOSH_TEST_SSH_HOST")
        .ok()
        .filter(|s| !s.is_empty())
}

fn test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn temp_socket_path(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sloosh-fwd-itest-{tag}-{}-{}",
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

/// Grant this test process itself a lease for `host` (docs/internals/architecture.md), same
/// approach as `tests/ssh_session.rs::grant_lease_for_test`.
async fn grant_lease_for_test(host: &str, use_vault_profile: bool) {
    if !vault::exists() {
        let mut data = vault::VaultData::default();
        if use_vault_profile {
            data.hosts.insert(
                host.to_string(),
                vault::HostEntry {
                    hostname: host.to_string(),
                    port: Some(22),
                    user: None,
                    auth: vault::AuthMethod::Agent,
                    route: sloosh::proto::HostRoute::Direct,
                },
            );
        }
        vault::create(&data, b"sloosh-live-test-master-password").expect("create test vault");
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

async fn start_daemon(
    tag: &str,
    host: &str,
    use_vault_profile: bool,
) -> (UnixChannel, std::path::PathBuf) {
    set_test_home(tag);
    grant_lease_for_test(host, use_vault_profile).await;
    let socket_path = temp_socket_path(tag);
    let daemon_socket = socket_path.clone();
    tokio::spawn(async move {
        let _ = sloosh::daemon::run(daemon_socket).await;
    });
    let chan = connect_with_retry(&socket_path).await;
    (chan, socket_path)
}

#[tokio::test]
async fn remote_forward_dispatches_to_remote_parser_without_network() {
    let _guard = test_lock().lock().await;
    let host = "remote-forward-parser.invalid";
    let (mut chan, _socket) = start_daemon("remote-parser", host, true).await;

    chan.send(&Request::Forward {
        host: host.to_string(),
        direction: ForwardDirection::Remote {
            spec: "9000:127.0.0.1:0".to_string(),
        },
        lease_token: None,
    })
    .await
    .expect("send remote Forward");

    let Some(Response::Error { message }) = chan.recv::<Response>().await.expect("recv") else {
        panic!("zero local target port should fail during remote spec parsing");
    };
    assert!(message.contains("targets port 0"), "{message}");
    assert!(!message.contains("temporarily disabled"), "{message}");
}

async fn start_local_echo() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind local echo listener");
    let port = listener.local_addr().expect("echo listener address").port();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.expect("accept reverse tunnel");
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (port, task)
}

fn remote_port(listen_addr: &str) -> u16 {
    listen_addr
        .rsplit_once(':')
        .expect("remote listen address contains a port")
        .1
        .parse()
        .expect("remote listen port is numeric")
}

async fn wait_for_remote_listener_close(connection: &ssh::Connection, port: u16) {
    for _ in 0..100 {
        if connection
            .handle
            .channel_open_direct_tcpip("127.0.0.1", port as u32, "127.0.0.1", 0)
            .await
            .is_err()
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("remote forward listener still accepted connections after teardown");
}

#[tokio::test]
async fn remote_forward_tunnels_to_local_target_and_stops_cleanly() {
    let _guard = test_lock().lock().await;
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (local_port, echo_task) = start_local_echo().await;
    let (mut chan, _socket) = start_daemon("remote-forward", &host, false).await;

    chan.send(&Request::Forward {
        host: host.clone(),
        direction: ForwardDirection::Remote {
            spec: format!("0:127.0.0.1:{local_port}"),
        },
        lease_token: None,
    })
    .await
    .expect("send remote Forward");
    let Some(Response::Forward(opened)) = chan.recv::<Response>().await.expect("recv") else {
        panic!("expected Response::Forward");
    };
    assert_eq!(opened.direction, "R");
    let port = remote_port(&opened.listen_addr);

    let connection = ssh::connect(
        &host,
        &LeaseContext {
            caller_pid: std::process::id(),
            lease_token: None,
        },
    )
    .await
    .expect("open verifier SSH connection");
    let channel = connection
        .handle
        .channel_open_direct_tcpip("127.0.0.1", port as u32, "127.0.0.1", 0)
        .await
        .expect("connect to remote listener");
    let mut tunnel = channel.into_stream();
    tunnel.write_all(b"reverse-forward").await.expect("send");
    let mut echoed = [0u8; 15];
    tunnel.read_exact(&mut echoed).await.expect("receive echo");
    assert_eq!(&echoed, b"reverse-forward");

    chan.send(&Request::ForwardStop {
        id: opened.id.clone(),
    })
    .await
    .expect("send ForwardStop");
    assert_eq!(
        chan.recv::<Response>().await.expect("recv"),
        Some(Response::Ok)
    );

    let mut byte = [0u8; 1];
    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), tunnel.read(&mut byte))
        .await
        .expect("active reverse tunnel did not close after stop");
    assert!(matches!(closed, Ok(0) | Err(_)));
    wait_for_remote_listener_close(&connection, port).await;
    echo_task.abort();
    let _ = echo_task.await;
}

#[cfg(feature = "integration-test-hooks")]
#[tokio::test]
async fn remote_forward_listener_and_tunnel_close_when_lease_expires() {
    let _guard = test_lock().lock().await;
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (local_port, echo_task) = start_local_echo().await;
    let (mut chan, _socket) = start_daemon("remote-expiry", &host, false).await;

    chan.send(&Request::Forward {
        host: host.clone(),
        direction: ForwardDirection::Remote {
            spec: format!("0:127.0.0.1:{local_port}"),
        },
        lease_token: None,
    })
    .await
    .expect("send remote Forward");
    let Some(Response::Forward(opened)) = chan.recv::<Response>().await.expect("recv") else {
        panic!("expected Response::Forward");
    };
    let port = remote_port(&opened.listen_addr);
    let connection = ssh::connect(
        &host,
        &LeaseContext {
            caller_pid: std::process::id(),
            lease_token: None,
        },
    )
    .await
    .expect("open verifier SSH connection");
    let channel = connection
        .handle
        .channel_open_direct_tcpip("127.0.0.1", port as u32, "127.0.0.1", 0)
        .await
        .expect("connect to remote listener");
    let mut tunnel = channel.into_stream();
    tunnel.write_all(b"before-expiry").await.expect("send");
    let mut echoed = [0u8; 13];
    tunnel.read_exact(&mut echoed).await.expect("receive echo");
    assert_eq!(&echoed, b"before-expiry");

    lease::expire_active_leases_for_integration_test().await;
    sloosh::daemon::forward::reap_expired_leases_for_integration_test().await;

    chan.send(&Request::ForwardLs)
        .await
        .expect("send ForwardLs");
    let Some(Response::ForwardLs { forwards }) = chan.recv::<Response>().await.expect("recv")
    else {
        panic!("expected Response::ForwardLs");
    };
    assert!(forwards.is_empty());
    let mut byte = [0u8; 1];
    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), tunnel.read(&mut byte))
        .await
        .expect("active reverse tunnel did not close after lease expiry");
    assert!(matches!(closed, Ok(0) | Err(_)));
    wait_for_remote_listener_close(&connection, port).await;
    echo_task.abort();
    let _ = echo_task.await;
}

#[tokio::test]
async fn local_forward_tunnels_to_remote_sshd_and_stops_cleanly() {
    let _guard = test_lock().lock().await;
    let Some(host) = test_host() else {
        eprintln!("SLOOSH_TEST_SSH_HOST not set; skipping live SSH test");
        return;
    };
    let (mut chan, _socket) = start_daemon("local-forward", &host, false).await;

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
