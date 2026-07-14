//! Live-SSH integration test for vault-backed ProxyJump chains: a vault
//! entry whose `jump` field routes the connection through
//! another vault entry, with per-hop lease enforcement. Gated behind BOTH
//! `SLOOSH_TEST_SSH_HOST` (a `user@host` literal or bare host) and
//! `SLOOSH_TEST_SSH_PASSWORD` (that host's SSH password) — see
//! tests/ssh_session.rs's module doc for the harness rationale and the
//! `--test-threads=1` requirement.
//!
//! Needs only ONE live host to exercise a real two-hop dial: both entries
//! point at the same address, so the "chain" is host → direct-tcpip back to
//! the host's own sshd (hairpin). That still drives the full machinery for
//! real: vault jump resolution, `channel_open_direct_tcpip` through the
//! hop, a second handshake + password auth over the tunneled stream, host
//! key verification for the tunneled target, and the per-hop lease check.
//! (The target deliberately reuses the host's public address rather than
//! `127.0.0.1` — known-hosts lookups use the logical target name, exactly
//! like OpenSSH ProxyJump, and `127.0.0.1` would collide with whatever key
//! the developer's own machine has recorded under that name.)
//!
//! Deny and allow are ONE test on purpose: lease state is process-global,
//! so a separate deny test would inherit the allow test's grants (or vice
//! versa) and assert nothing.

use sloosh::daemon::{lease, vault};
use sloosh::proto::{Request, Response, WIRE_PROTOCOL_VERSION};
use sloosh::transport::Channel;
use sloosh::transport::unix::UnixChannel;

const MASTER: &[u8] = b"sloosh-live-test-master-password";
const HOP: &str = "livehop";
const TARGET: &str = "livetarget";

fn test_creds() -> Option<(String, Option<String>, String)> {
    let dest = std::env::var("SLOOSH_TEST_SSH_HOST")
        .ok()
        .filter(|s| !s.is_empty())?;
    let password = std::env::var("SLOOSH_TEST_SSH_PASSWORD")
        .ok()
        .filter(|s| !s.is_empty())?;
    let (user, host) = match dest.rsplit_once('@') {
        Some((u, h)) => (Some(u.to_string()), h.to_string()),
        None => (None, dest),
    };
    Some((host, user, password))
}

fn set_test_home(tag: &str) {
    let home =
        std::env::temp_dir().join(format!("sloosh-pj-itest-home-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&home).expect("create test SLOOSH_HOME");
    // SAFETY: see tests/ssh_session.rs::set_test_home — manual, gated,
    // single-threaded runs only.
    unsafe {
        std::env::set_var("SLOOSH_HOME", &home);
    }
}

/// Vault with two password entries pointing at the same live host:
/// `livehop` directly, `livetarget` through `jump = livehop`.
fn create_chain_vault(host: &str, user: &Option<String>, password: &str) {
    let entry = |jump: Option<String>| vault::HostEntry {
        hostname: host.to_string(),
        port: Some(22),
        user: user.clone(),
        auth: vault::AuthMethod::Password {
            password: password.to_string(),
        },
        jump,
    };
    let mut data = vault::VaultData::default();
    data.hosts.insert(HOP.to_string(), entry(None));
    data.hosts
        .insert(TARGET.to_string(), entry(Some(HOP.to_string())));
    vault::create(&data, MASTER).expect("create chain test vault");
}

async fn grant_lease(hosts: &[&str]) {
    let pid = std::process::id();
    match lease::request_lease(pid, hosts.iter().map(|h| h.to_string()).collect())
        .await
        .expect("request test lease")
    {
        lease::RequestOutcome::AlreadyAuthorized => {}
        lease::RequestOutcome::Pending(info) => {
            lease::approve_lease_for_chain(&[], &info.id, MASTER)
                .await
                .expect("approve test lease");
        }
    }
}

async fn start_daemon(tag: &str) -> UnixChannel {
    let dir = std::env::temp_dir().join(format!("sloosh-pj-itest-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create private socket dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("secure socket dir");
    }
    let socket_path = dir.join("sloosh.sock");
    let daemon_socket = socket_path.clone();
    tokio::spawn(async move {
        let _ = sloosh::daemon::run(daemon_socket).await;
    });
    let mut delay = std::time::Duration::from_millis(10);
    for _ in 0..50 {
        if let Ok(mut chan) = UnixChannel::connect(&socket_path).await {
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
    panic!(
        "daemon never became connectable at {}",
        socket_path.display()
    );
}

async fn run_on_target(chan: &mut UnixChannel, command: &str) -> Response {
    chan.send(&Request::Run {
        host: TARGET.to_string(),
        command: command.to_string(),
        session: None,
        timeout_secs: 60,
        raw: false,
        lease_token: None,
    })
    .await
    .expect("send Run");
    chan.recv::<Response>().await.expect("recv").expect("some")
}

#[tokio::test]
async fn vault_jump_denies_unleased_hop_then_runs_with_full_chain_lease() {
    let Some((host, user, password)) = test_creds() else {
        eprintln!("SLOOSH_TEST_SSH_HOST/SLOOSH_TEST_SSH_PASSWORD not set; skipping");
        return;
    };
    set_test_home("chain");
    create_chain_vault(&host, &user, &password);
    let mut chan = start_daemon("chain").await;

    // Phase 1: only the target is leased. The vault-backed hop must refuse
    // the dial with a teaching error naming itself — the target's lease
    // alone doesn't authorize the bastion.
    grant_lease(&[TARGET]).await;
    let resp = run_on_target(&mut chan, "echo should-not-run").await;
    let Response::Error { message } = resp else {
        panic!("expected Response::Error, got {resp:?}");
    };
    assert!(
        message.contains(HOP) && message.contains("lease"),
        "error should name the unleased hop and mention the lease: {message:?}"
    );

    // Phase 2: lease the hop too; the same command now runs end-to-end
    // through the tunneled second handshake.
    grant_lease(&[HOP]).await;
    let resp = run_on_target(&mut chan, "echo sloosh-chain-$((6*7))").await;
    let Response::Run(reply) = resp else {
        panic!("expected Response::Run, got {resp:?}");
    };
    assert_eq!(reply.state, "done");
    assert_eq!(reply.exit_code, Some(0));
    assert!(
        reply.output.contains("sloosh-chain-42"),
        "unexpected output: {:?}",
        reply.output
    );
}
