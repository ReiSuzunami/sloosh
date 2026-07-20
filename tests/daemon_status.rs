//! Integration test: start the daemon against a temp socket path, connect
//! as a client, send `Status`, check the reply — end-to-end proof the
//! accept loop and NDJSON framing work together (docs/internals/architecture.md milestone 1).
//!
//! The socket path is overridable via `SLOOSH_SOCKET` (checked here through
//! `transport::unix::resolve_socket_path`, same code path the real CLI
//! uses) specifically so tests don't collide with a real user's daemon.

use sloosh::proto::{
    HostAuth, HostAuthKind, HostRoute, HostSummary, Request, Response, SecretString,
    WIRE_PROTOCOL_VERSION,
};
use sloosh::transport::Channel;
use sloosh::transport::unix::UnixChannel;

fn temp_socket_path(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sloosh-itest-{tag}-{}-{}",
        std::process::id(),
        tag.len() // trivial extra entropy so parallel calls with the same tag still differ
    ));
    std::fs::create_dir_all(&dir).expect("create private test directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("secure private test directory");
    }
    dir.join("sloosh.sock")
}

#[tokio::test]
async fn status_round_trip_against_running_daemon() {
    let socket_path = temp_socket_path("status");
    let test_home = socket_path
        .parent()
        .expect("test socket has a parent")
        .join("home");
    // SAFETY: this test process does not read SLOOSH_SOCKET concurrently
    // from another thread in a way that would race with this write.
    unsafe {
        std::env::set_var("SLOOSH_SOCKET", &socket_path);
        std::env::set_var("SLOOSH_HOME", &test_home);
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
    assert_eq!(reply.wire_protocol, WIRE_PROTOCOL_VERSION);
    assert!(reply.sessions.is_empty());
    assert!(reply.leases.is_empty());

    // An old CLI can parse and send current request shapes without knowing
    // that transfers now switch into raw framing. Reject before lease checks,
    // SFTP setup, or remote-file creation can run.
    chan.send(&Request::Put {
        host: "must-not-connect.invalid".to_string(),
        local_path: "/local/label-only".to_string(),
        remote_path: "/must-not-be-created".to_string(),
        session: None,
        lease_token: None,
    })
    .await
    .expect("send unnegotiated Put");
    let denied = chan.recv::<Response>().await.expect("recv denial");
    let Some(Response::Error { message }) = denied else {
        panic!("expected protocol denial, got {denied:?}");
    };
    assert!(message.contains("protocol handshake required"), "{message}");
    assert!(message.contains("Put"), "{message}");

    let wrong_protocol = WIRE_PROTOCOL_VERSION.saturating_sub(1);
    chan.send(&Request::Hello {
        wire_protocol: wrong_protocol,
    })
    .await
    .expect("send incompatible Hello");
    let denied = chan.recv::<Response>().await.expect("recv Hello denial");
    let Some(Response::Error { message }) = denied else {
        panic!("expected incompatible protocol denial, got {denied:?}");
    };
    assert!(message.contains("incompatible wire protocol"), "{message}");

    chan.send(&Request::Hello {
        wire_protocol: WIRE_PROTOCOL_VERSION,
    })
    .await
    .expect("send compatible Hello");
    assert_eq!(
        chan.recv::<Response>().await.expect("recv ProtocolReady"),
        Some(Response::ProtocolReady {
            wire_protocol: WIRE_PROTOCOL_VERSION,
        })
    );

    chan.send(&Request::InitVault {
        master_password: SecretString::new("masterpw"),
    })
    .await
    .expect("send InitVault");
    assert_eq!(
        chan.recv::<Response>().await.expect("recv InitVault"),
        Some(Response::Ok)
    );

    chan.send(&Request::AddCred {
        alias: "web".to_string(),
        hostname: "web.example.com".to_string(),
        port: None,
        user: Some("deploy".to_string()),
        auth: HostAuth::Password {
            password: SecretString::new("sshpw"),
        },
        master_password: SecretString::new("masterpw"),
        replace: false,
        route: HostRoute::Direct,
    })
    .await
    .expect("send AddCred");
    assert_eq!(
        chan.recv::<Response>().await.expect("recv AddCred"),
        Some(Response::Ok)
    );

    chan.send(&Request::ListHosts {
        master_password: SecretString::new("masterpw"),
    })
    .await
    .expect("send ListHosts");
    assert_eq!(
        chan.recv::<Response>().await.expect("recv ListHosts"),
        Some(Response::Hosts {
            hosts: vec![HostSummary {
                alias: "web".to_string(),
                hostname: "web.example.com".to_string(),
                port: None,
                user: Some("deploy".to_string()),
                auth: HostAuthKind::Password,
                route: HostRoute::Direct,
            }],
        })
    );

    chan.send(&Request::UpdateHost {
        alias: "web".to_string(),
        hostname: "web.internal.example".to_string(),
        port: Some(2222),
        user: Some("operator".to_string()),
        route: HostRoute::ProxyJump {
            spec: "bastion".to_string(),
        },
        auth: None,
        master_password: SecretString::new("masterpw"),
    })
    .await
    .expect("send UpdateHost");
    assert_eq!(
        chan.recv::<Response>().await.expect("recv UpdateHost"),
        Some(Response::Ok)
    );

    chan.send(&Request::UpdateHost {
        alias: "web".to_string(),
        hostname: String::new(),
        port: None,
        user: None,
        route: HostRoute::Direct,
        auth: None,
        master_password: SecretString::new("masterpw"),
    })
    .await
    .expect("send malformed UpdateHost");
    let invalid_update = chan
        .recv::<Response>()
        .await
        .expect("recv malformed-update response");
    assert!(
        matches!(invalid_update, Some(Response::Error { ref message }) if message.contains("hostname cannot be empty")),
        "{invalid_update:?}"
    );

    chan.send(&Request::ListHosts {
        master_password: SecretString::new("masterpw"),
    })
    .await
    .expect("send ListHosts after rejected update");
    assert_eq!(
        chan.recv::<Response>()
            .await
            .expect("recv unchanged ListHosts"),
        Some(Response::Hosts {
            hosts: vec![HostSummary {
                alias: "web".to_string(),
                hostname: "web.internal.example".to_string(),
                port: Some(2222),
                user: Some("operator".to_string()),
                auth: HostAuthKind::Password,
                route: HostRoute::ProxyJump {
                    spec: "bastion".to_string()
                },
            }],
        })
    );

    chan.send(&Request::ListHosts {
        master_password: SecretString::new("wrong"),
    })
    .await
    .expect("send ListHosts with wrong password");
    let wrong_password = chan
        .recv::<Response>()
        .await
        .expect("recv wrong-password response");
    assert!(
        matches!(wrong_password, Some(Response::Error { ref message }) if message.contains("wrong master password")),
        "{wrong_password:?}"
    );

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
