use sloosh::client::DaemonClient;
use sloosh::proto::{HostAuth, HostRoute, Request, Response, SecretString};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

struct Home(PathBuf);
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn start(home: &Path, bypass: bool) -> (tokio::process::Child, DaemonClient) {
    let daemon = PathBuf::from(env!("CARGO_BIN_EXE_slooshd"));
    let socket = home.join("s");
    let mut command = tokio::process::Command::new(&daemon);
    if bypass {
        command.arg("--dangerous-bypass-mode");
    }
    let child = command
        .env("SLOOSH_HOME", home)
        .env("SLOOSH_SOCKET", &socket)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if tokio::net::UnixStream::connect(&socket).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (child, DaemonClient::new(socket, daemon))
}
async fn stop(mut child: tokio::process::Child, client: DaemonClient) {
    assert_eq!(
        client.request(&Request::Shutdown).await.unwrap(),
        Response::Ok
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}
fn master() -> SecretString {
    SecretString::new("isolated-test-only")
}
fn add(alias: &str) -> Request {
    Request::AddCred {
        alias: alias.into(),
        hostname: "127.0.0.1".into(),
        port: Some(1),
        user: Some("fixture".into()),
        auth: HostAuth::Password {
            password: SecretString::new("not-a-real-credential"),
        },
        master_password: master(),
        replace: false,
        route: HostRoute::Direct,
    }
}

#[tokio::test]
async fn bypass_human_operations_unlock_new_and_existing_credentials_without_approval() {
    use std::os::unix::fs::PermissionsExt;
    let home = Home(std::env::temp_dir().join(format!("sloosh-c-{:x}", rand::random::<u32>())));
    std::fs::create_dir(&home.0).unwrap();
    std::fs::set_permissions(&home.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    // Normal mode writes credentials without changing cache/lease authority.
    let (child, client) = start(&home.0, false).await;
    assert_eq!(
        client
            .request(&Request::InitVault {
                master_password: master()
            })
            .await
            .unwrap(),
        Response::Ok
    );
    assert_eq!(
        client.request(&add("existing.invalid")).await.unwrap(),
        Response::Ok
    );
    stop(child, client).await;
    let (child, client) = start(&home.0, true).await;
    let request = || Request::RequestLease {
        hosts: vec!["added.invalid".into()],
    };
    assert!(
        matches!(client.request(&request()).await.unwrap(),Response::Error{message} if message.contains("vault is locked"))
    );
    // First add before any active lease must publish a bounded unlock.
    assert_eq!(
        client.request(&add("added.invalid")).await.unwrap(),
        Response::Ok
    );
    assert_eq!(client.request(&request()).await.unwrap(), Response::Ok);
    let result = client
        .request(&Request::Run {
            host: "added.invalid".into(),
            command: "true".into(),
            session: None,
            timeout_secs: 1,
            raw: false,
            lease_token: None,
        })
        .await
        .unwrap();
    assert!(
        matches!(result,Response::Error{message} if message.contains("127.0.0.1:1")),
        "the vault endpoint, never the alias, must be dialed"
    );
    stop(child, client).await;
    // Restart forgets the key, not the encrypted records.
    let (child, client) = start(&home.0, true).await;
    assert!(
        matches!(client.request(&request()).await.unwrap(),Response::Error{message} if message.contains("vault is locked"))
    );
    assert!(matches!(
        client
            .request(&Request::ListHosts {
                master_password: SecretString::new("wrong")
            })
            .await
            .unwrap(),
        Response::Error { .. }
    ));
    assert!(
        matches!(client.request(&request()).await.unwrap(),Response::Error{message} if message.contains("vault is locked"))
    );
    assert!(
        matches!(client.request(&Request::ListHosts{master_password:master()}).await.unwrap(),Response::Hosts{hosts} if hosts.len()==2)
    );
    assert_eq!(client.request(&request()).await.unwrap(), Response::Ok);
    stop(child, client).await;
}
