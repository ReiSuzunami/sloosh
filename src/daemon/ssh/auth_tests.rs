use super::*;
use russh::keys::{signature::Signer as _, ssh_encoding::Encode as _, ssh_key};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let nonce = rand::random::<u64>();
        let root = std::env::temp_dir().join(format!("sloosh-a-{:x}", nonce as u32));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn key_path(&self) -> PathBuf {
        self.0.join("key")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn ed25519_key() -> PrivateKey {
    PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap()
}

#[test]
fn vault_key_file_reads_encrypted_public_identity_without_decryption() {
    let fixture = Fixture::new();
    let key = ed25519_key();
    let encrypted = key
        .encrypt(&mut russh::keys::key::safe_rng(), "test-passphrase")
        .unwrap();
    encrypted
        .write_openssh_file(fixture.key_path(), ssh_key::LineEnding::LF)
        .unwrap();
    let loaded = load_vault_key_file(&fixture.key_path()).unwrap();
    assert!(loaded.is_encrypted());
    assert_eq!(loaded.public_key().key_data(), key.public_key().key_data());
    // The KeyFile authority does not become an automatic Agent lease.
    assert!(!auth_matches_system_agent_policy(
        Some(&vault::AuthMethod::KeyFile {
            path: fixture.key_path().to_string_lossy().into_owned(),
        }),
        None
    ));

    key.write_openssh_file(fixture.key_path(), ssh_key::LineEnding::LF)
        .unwrap();
    let loaded = load_vault_key_file(&fixture.key_path()).unwrap();
    assert!(!loaded.is_encrypted());
    assert_eq!(loaded.algorithm(), Algorithm::Ed25519);
}

#[test]
fn vault_key_file_reads_rsa_public_identity_without_signing() {
    let fixture = Fixture::new();
    let key = PrivateKey::random(
        &mut russh::keys::key::safe_rng(),
        Algorithm::Rsa { hash: None },
    )
    .unwrap();
    key.write_openssh_file(fixture.key_path(), ssh_key::LineEnding::LF)
        .unwrap();
    let loaded = load_vault_key_file(&fixture.key_path()).unwrap();
    assert!(matches!(loaded.algorithm(), Algorithm::Rsa { .. }));
    assert_eq!(loaded.public_key().key_data(), key.public_key().key_data());
    assert!(!auth_matches_system_agent_policy(
        Some(&vault::AuthMethod::KeyFile {
            path: fixture.key_path().to_string_lossy().into_owned(),
        }),
        None
    ));
}

#[test]
fn vault_key_file_rejects_unsupported_encryption_and_oversized_files() {
    let fixture = Fixture::new();
    // PKCS#8's encrypted payload has no public identity outside the cipher.
    let mut pem = Zeroizing::new(Vec::new());
    russh::keys::encode_pkcs8_pem_encrypted(&ed25519_key(), b"test-passphrase", 1, &mut *pem)
        .unwrap();
    std::fs::write(fixture.key_path(), &*pem).unwrap();
    assert!(matches!(
        load_vault_key_file(&fixture.key_path()),
        Err(SshError::KeyFilePublicIdentityUnavailable { .. })
    ));
    std::fs::write(
        fixture.key_path(),
        vec![b'x'; MAX_VAULT_KEY_FILE_BYTES as usize + 1],
    )
    .unwrap();
    assert!(matches!(
        load_vault_key_file(&fixture.key_path()),
        Err(SshError::KeyFileTooLarge { .. })
    ));
}

struct TestClient;

#[tokio::test]
async fn host_key_probe_rejects_certificates_without_capturing_subject_key() {
    let key = ed25519_key();
    let mut builder = ssh_key::certificate::Builder::new(
        vec![0; 16],
        key.public_key().key_data().clone(),
        0,
        u64::MAX,
    )
    .unwrap();
    builder
        .cert_type(ssh_key::certificate::CertType::Host)
        .unwrap();
    builder.all_principals_valid().unwrap();
    let certificate = PublicKeyOrCertificate::Certificate(builder.sign(&key).unwrap());
    let captured = Arc::new(Mutex::new(None));
    let mut handler = KeyCapturingHandler {
        captured: captured.clone(),
    };
    assert!(
        !russh::client::Handler::check_server_key(&mut handler, &certificate)
            .await
            .unwrap()
    );
    assert!(captured.lock().unwrap().is_none());
}

impl russh::client::Handler for TestClient {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(matches!(key, PublicKeyOrCertificate::PublicKey { .. }))
    }
}

struct TestServer {
    offered: Arc<Mutex<Vec<PublicKey>>>,
    accept: bool,
}

struct PasswordServer {
    seen: Arc<Mutex<Option<String>>>,
}
impl russh::server::Handler for PasswordServer {
    type Error = russh::Error;
    async fn auth_password(
        &mut self,
        _: &str,
        password: &str,
    ) -> Result<russh::server::Auth, Self::Error> {
        *self.seen.lock().unwrap() = Some(password.to_string());
        Ok(russh::server::Auth::Accept)
    }
}

#[tokio::test]
async fn connection_auth_uses_the_resolved_snapshot_after_host_edit() {
    let _guard = vault::cache_test_lock().lock().await;
    vault::clear_cache().await;
    let path = vault::vault_path();
    let _ = std::fs::remove_file(&path);
    vault::add_entry(
        "snapshot",
        vault::HostEntry {
            hostname: "endpoint-a.invalid".into(),
            port: Some(22),
            user: Some("user-a".into()),
            route: crate::proto::HostRoute::Direct,
            auth: vault::AuthMethod::Password {
                password: "fixture-old".into(),
            },
        },
        b"fixture",
        false,
    )
    .await
    .unwrap();
    // Cold vault must fail, never reinterpret a vault alias as DNS/config.
    assert!(matches!(
        resolve_host_config(&SshConfig::default(), "snapshot").await,
        Err(SshError::VaultLocked)
    ));
    vault::unlock_for_lease(b"fixture").await.unwrap();
    let resolved = resolve_host_config(&SshConfig::default(), "snapshot")
        .await
        .unwrap();
    vault::update_entry(
        vault::HostUpdate {
            alias: "snapshot".into(),
            hostname: "endpoint-b.invalid".into(),
            port: Some(22),
            user: Some("user-b".into()),
            route: crate::proto::HostRoute::Direct,
        },
        Some(vault::AuthMethod::Password {
            password: "fixture-new".into(),
        }),
        b"fixture",
    )
    .await
    .unwrap();
    assert_eq!(resolved.hostname, "endpoint-a.invalid");
    let seen = Arc::new(Mutex::new(None));
    let capture = seen.clone();
    let (client_stream, server_stream) = tokio::io::duplex(65536);
    let config = russh::server::Config {
        keys: vec![ed25519_key()],
        auth_rejection_time: Duration::ZERO,
        ..Default::default()
    };
    let server = tokio::spawn(async move {
        russh::server::run_stream(
            Arc::new(config),
            server_stream,
            PasswordServer { seen: capture },
        )
        .await
        .unwrap()
        .await
        .unwrap();
    });
    let mut handle = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        TestClient,
    )
    .await
    .unwrap();
    authenticate(&mut handle, &resolved, false).await.unwrap();
    assert_eq!(seen.lock().unwrap().as_deref(), Some("fixture-old"));
    server.abort();
    vault::clear_cache().await;
    let _ = std::fs::remove_file(path);
}
impl russh::server::Handler for TestServer {
    type Error = russh::Error;
    async fn auth_publickey_offered(
        &mut self,
        _: &str,
        key: &PublicKey,
    ) -> Result<russh::server::Auth, Self::Error> {
        self.offered.lock().unwrap().push(key.clone());
        Ok(if self.accept {
            russh::server::Auth::Accept
        } else {
            russh::server::Auth::reject()
        })
    }
    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &PublicKey,
    ) -> Result<russh::server::Auth, Self::Error> {
        Ok(russh::server::Auth::Accept)
    }
}

fn put_string(buffer: &mut Vec<u8>, value: &[u8]) {
    buffer.extend_from_slice(&(value.len() as u32).to_be_bytes());
    buffer.extend_from_slice(value);
}
fn take_string<'a>(input: &mut &'a [u8]) -> &'a [u8] {
    let len = u32::from_be_bytes(input[..4].try_into().unwrap()) as usize;
    let value = &input[4..4 + len];
    *input = &input[4 + len..];
    value
}

// Tiny test-only agent: identity enumeration and Ed25519 signing over a UDS.
// Never touches the user's agent, private files, or network.
async fn serve_agent(
    listener: tokio::net::UnixListener,
    keys: Vec<PrivateKey>,
    signed: Arc<Mutex<Vec<PublicKey>>>,
) {
    let (mut stream, _) = listener.accept().await.unwrap();
    while let Ok(len) = stream.read_u32().await {
        assert!(len < 65536);
        let mut packet = vec![0; len as usize];
        stream.read_exact(&mut packet).await.unwrap();
        let mut reply = Vec::new();
        match packet[0] {
            11 => {
                // SSH_AGENTC_REQUEST_IDENTITIES
                reply.push(12);
                reply.extend_from_slice(&(keys.len() as u32).to_be_bytes());
                for key in &keys {
                    put_string(&mut reply, &key.public_key().to_bytes().unwrap());
                    put_string(&mut reply, b"different agent comment");
                }
            }
            13 => {
                // SSH_AGENTC_SIGN_REQUEST
                let mut input = &packet[1..];
                let requested = PublicKey::from_bytes(take_string(&mut input)).unwrap();
                let data = take_string(&mut input);
                let key = keys
                    .iter()
                    .find(|key| key.public_key().key_data() == requested.key_data())
                    .unwrap();
                signed.lock().unwrap().push(requested);
                let signature: ssh_key::Signature = key.try_sign(data).unwrap();
                let mut blob = Vec::new();
                signature.encode(&mut blob).unwrap();
                reply.push(14);
                put_string(&mut reply, &blob);
            }
            _ => panic!("unexpected agent request"),
        }
        stream.write_u32(reply.len() as u32).await.unwrap();
        stream.write_all(&reply).await.unwrap();
    }
}

async fn exact_agent_case(include_matching: bool, accept: bool, disabled: bool) {
    let fixture = Fixture::new();
    let desired = ed25519_key();
    let wrong = ed25519_key();
    let listener = tokio::net::UnixListener::bind(fixture.0.join("a")).unwrap();
    let signed = Arc::new(Mutex::new(Vec::new()));
    let mut keys = vec![wrong];
    if include_matching {
        keys.extend([desired.clone(), desired.clone()]);
    }
    let agent_task = tokio::spawn(serve_agent(listener, keys, signed.clone()));
    let offered = Arc::new(Mutex::new(Vec::new()));
    let server_config = russh::server::Config {
        keys: vec![ed25519_key()],
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    };
    let (client_stream, server_stream) = tokio::io::duplex(65536);
    let server_offered = offered.clone();
    let server_task = tokio::spawn(async move {
        russh::server::run_stream(
            Arc::new(server_config),
            server_stream,
            TestServer {
                offered: server_offered,
                accept,
            },
        )
        .await
        .unwrap()
        .await
        .unwrap();
    });
    let mut handle = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        TestClient,
    )
    .await
    .unwrap();
    let mut config = SshConfig::default().resolve("test");
    config.identity_agent = Some(if disabled {
        IdentityAgentValue::Disabled
    } else {
        IdentityAgentValue::Path(fixture.0.join("a"))
    });
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        try_agent_auth(&mut handle, &config, None, Some(desired.public_key())),
    )
    .await
    .unwrap();
    let expected = if disabled {
        Err(AgentAuthFailure::Disabled)
    } else if !include_matching {
        Err(AgentAuthFailure::NoMatchingIdentity)
    } else if !accept {
        Err(AgentAuthFailure::Rejected)
    } else {
        Ok(())
    };
    assert_eq!(result, expected);
    let attempts = offered.lock().unwrap();
    assert_eq!(attempts.len(), usize::from(include_matching && !disabled));
    for key in attempts.iter() {
        assert_eq!(key.key_data(), desired.public_key().key_data());
    }
    assert_eq!(
        signed.lock().unwrap().len(),
        usize::from(include_matching && accept && !disabled)
    );
    drop(attempts);
    agent_task.abort();
    server_task.abort();
}

#[tokio::test]
async fn exact_key_file_agent_signs_only_the_selected_identity() {
    exact_agent_case(true, true, false).await;
    exact_agent_case(false, true, false).await;
    exact_agent_case(true, false, false).await;
    exact_agent_case(true, true, true).await;
}

#[test]
fn exact_key_file_agent_errors_quote_paths_and_do_not_suggest_loading_after_rejection() {
    let mut config = SshConfig::default().resolve("test");
    config.identity_agent = Some(IdentityAgentValue::Path(PathBuf::from(
        "/tmp/agent's socket",
    )));
    let path = PathBuf::from("/tmp/key's file");
    let error = key_file_agent_error(path.clone(), &config, AgentAuthFailure::NoMatchingIdentity)
        .to_string();
    assert!(
        error.contains("SSH_AUTH_SOCK='/tmp/agent'\\''s socket' ssh-add '/tmp/key'\\''s file'")
    );
    let rejected = key_file_agent_error(path, &config, AgentAuthFailure::Rejected).to_string();
    assert!(!rejected.contains("ssh-add"));
}
