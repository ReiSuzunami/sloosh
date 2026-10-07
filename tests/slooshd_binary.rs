use std::process::Command;
use std::time::Duration;

use sloosh::client::DaemonClient;
use sloosh::proto::{Request, Response};

#[test]
fn dedicated_daemon_has_its_own_minimal_cli_surface() {
    let daemon = env!("CARGO_BIN_EXE_slooshd");
    let version = Command::new(daemon)
        .arg("--version")
        .output()
        .expect("run slooshd --version");
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).expect("version is utf-8"),
        format!("slooshd {}\n", env!("CARGO_PKG_VERSION"))
    );

    let legacy = Command::new(daemon)
        .args(["daemon", "run"])
        .output()
        .expect("run legacy daemon command");
    assert!(!legacy.status.success());
    let help = Command::new(daemon).arg("--help").output().unwrap();
    assert!(String::from_utf8_lossy(&help.stdout).contains("--dangerous-bypass-mode"));
}

#[tokio::test]
async fn dangerous_bypass_is_explicit_daemon_startup_policy() {
    use std::os::unix::fs::PermissionsExt;
    for (flag, configured) in [
        (false, None),
        (true, None),
        (false, Some(true)),
        (false, Some(false)),
        (true, Some(false)),
    ] {
        let enabled = flag || configured.unwrap_or(false);
        let root = std::env::temp_dir().join(format!(
            "sloosh-b-{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u32,
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        if let Some(configured) = configured {
            let settings = root.join("vault-settings.json");
            std::fs::write(&settings, format!(r#"{{"version":1,"idle_timeout_minutes":15,"dangerous_bypass_mode":{configured}}}"#)).unwrap();
            std::fs::set_permissions(settings, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        // A locked vault makes normal automatic system-agent approval ineligible.
        std::fs::write(root.join("vault"), b"locked test fixture").unwrap();
        let socket = root.join("s");
        let daemon = std::path::PathBuf::from(env!("CARGO_BIN_EXE_slooshd"));
        let mut command = tokio::process::Command::new(&daemon);
        if flag {
            command.arg("--dangerous-bypass-mode");
        }
        let mut child = command
            .env("SLOOSH_HOME", &root)
            .env("SLOOSH_SOCKET", &socket)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let client = DaemonClient::new(socket, daemon);
        let response = client
            .request(&Request::RequestLease {
                hosts: vec!["bypass-test.invalid".to_string()],
            })
            .await
            .unwrap();
        if enabled {
            assert!(
                matches!(response,Response::Error { message } if message.contains("automatic Keychain unlock failed") && message.contains("no host approval was requested"))
            );
        } else {
            assert!(matches!(response, Response::LeaseRequestPending(_)));
        }
        assert_eq!(
            client.request(&Request::Shutdown).await.unwrap(),
            Response::Ok
        );
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap();
        let audit = std::fs::read_to_string(root.join("audit.jsonl")).unwrap();
        assert!(!audit.contains("lease_approved_dangerous_bypass"));
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[tokio::test]
async fn dedicated_daemon_serves_verified_clients_without_cli_arguments() {
    use std::os::unix::fs::PermissionsExt;

    let daemon = std::path::PathBuf::from(env!("CARGO_BIN_EXE_slooshd"));
    let root = std::path::PathBuf::from("/tmp").join(format!(
        "sld-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    ));
    std::fs::create_dir(&root).expect("create isolated daemon home");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("secure isolated daemon home");
    let socket = root.join("sloosh.sock");

    let mut child = tokio::process::Command::new(&daemon)
        .env("SLOOSH_HOME", &root)
        .env("SLOOSH_SOCKET", &socket)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start dedicated daemon");

    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if !socket.exists() {
        let status = child.try_wait().expect("inspect slooshd status");
        let _ = child.kill().await;
        let output = child
            .wait_with_output()
            .await
            .expect("collect slooshd output");
        panic!(
            "slooshd did not bind its socket (early status: {status:?}): {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let client = DaemonClient::new(socket.clone(), daemon);
    let status = client.status().await.expect("verified daemon status");
    assert_eq!(status.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        client.request(&Request::Shutdown).await.expect("shutdown"),
        Response::Ok
    );

    let exit = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("slooshd should stop promptly")
        .expect("wait for slooshd");
    assert!(exit.success(), "slooshd exited with {exit}");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn daemon_stop_recovers_when_the_local_slooshd_file_is_missing() {
    use std::os::unix::fs::PermissionsExt;

    let root = std::path::PathBuf::from("/tmp").join(format!(
        "sld-stop-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    ));
    std::fs::create_dir(&root).expect("create isolated daemon home");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("secure isolated daemon home");
    let socket = root.join("sloosh.sock");
    let copied_cli = root.join("sloosh");
    std::fs::copy(env!("CARGO_BIN_EXE_sloosh"), &copied_cli).expect("copy CLI without slooshd");
    std::fs::set_permissions(&copied_cli, std::fs::Permissions::from_mode(0o755))
        .expect("make copied CLI executable");

    let absent = tokio::process::Command::new(&copied_cli)
        .args(["daemon", "status"])
        .env("SLOOSH_HOME", &root)
        .env("SLOOSH_SOCKET", &socket)
        .output()
        .await
        .expect("query absent daemon");
    assert!(
        absent.status.success(),
        "absent daemon status failed: {}",
        String::from_utf8_lossy(&absent.stderr)
    );
    assert!(
        String::from_utf8_lossy(&absent.stdout).contains("is not running"),
        "unexpected absent status: {}",
        String::from_utf8_lossy(&absent.stdout)
    );

    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_slooshd"))
        .env("SLOOSH_HOME", &root)
        .env("SLOOSH_SOCKET", &socket)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("start dedicated daemon");
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(socket.exists(), "slooshd did not bind its socket");

    let status = tokio::process::Command::new(&copied_cli)
        .args(["daemon", "status"])
        .env("SLOOSH_HOME", &root)
        .env("SLOOSH_SOCKET", &socket)
        .output()
        .await
        .expect("query daemon without local helper");
    assert!(
        !status.status.success(),
        "unverifiable daemon status must fail closed"
    );
    let status_error = String::from_utf8_lossy(&status.stderr);
    assert!(
        status_error.contains("daemon is listening"),
        "{status_error}"
    );
    assert!(
        status_error.contains("sloosh daemon stop"),
        "{status_error}"
    );

    let output = tokio::process::Command::new(&copied_cli)
        .args(["daemon", "stop"])
        .env("SLOOSH_HOME", &root)
        .env("SLOOSH_SOCKET", &socket)
        .output()
        .await
        .expect("run recovery stop");
    assert!(
        output.status.success(),
        "daemon stop failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let exit = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("slooshd should stop promptly")
        .expect("wait for slooshd");
    assert!(exit.success(), "slooshd exited with {exit}");
    let _ = std::fs::remove_dir_all(root);
}
