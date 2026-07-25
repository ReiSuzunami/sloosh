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
