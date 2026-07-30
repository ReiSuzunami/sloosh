use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

#[cfg(test)]
use data_encoding::BASE64;
use data_encoding::BASE64_MIME;
use hmac::{Hmac, KeyInit as _, Mac as _};
use rand::RngCore as _;
use russh::keys::{HashAlg, PublicKey};
use sha1::Sha1;

use super::SshError;
use crate::transport::unix::{ensure_private_dir, sloosh_home};

const MAX_KNOWN_HOSTS_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KnownHostSource {
    OpenSsh,
    Sloosh,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostKeyTrustState {
    Trusted,
    Unknown,
    Changed {
        source: KnownHostSource,
        stored_fingerprint: String,
        replaceable: bool,
    },
}

pub(crate) enum KnownHostMutation<'a> {
    Add,
    Replace { stored_fingerprint: &'a str },
}

pub(super) fn inspect_at_paths(
    hostname: &str,
    port: u16,
    observed: &PublicKey,
    openssh_path: &Path,
    sloosh_path: &Path,
) -> Result<HostKeyTrustState, SshError> {
    match inspect_path(hostname, port, observed, openssh_path)? {
        PathTrustState::Trusted => return Ok(HostKeyTrustState::Trusted),
        PathTrustState::Changed {
            stored_fingerprint, ..
        } => {
            return Ok(HostKeyTrustState::Changed {
                source: KnownHostSource::OpenSsh,
                stored_fingerprint,
                replaceable: false,
            });
        }
        PathTrustState::Missing => {}
    }

    match inspect_sloosh_path(hostname, port, observed, sloosh_path)? {
        PathTrustState::Trusted => Ok(HostKeyTrustState::Trusted),
        PathTrustState::Changed {
            stored_fingerprint,
            replaceable,
            ..
        } => Ok(HostKeyTrustState::Changed {
            source: KnownHostSource::Sloosh,
            stored_fingerprint,
            replaceable,
        }),
        PathTrustState::Missing => Ok(HostKeyTrustState::Unknown),
    }
}

enum PathTrustState {
    Trusted,
    Missing,
    Changed {
        stored_fingerprint: String,
        replaceable: bool,
    },
}

fn inspect_path(
    hostname: &str,
    port: u16,
    observed: &PublicKey,
    path: &Path,
) -> Result<PathTrustState, SshError> {
    let keys = russh::keys::known_hosts::known_host_keys_path(hostname, port, path)?;
    Ok(classify_known_keys(observed, &keys, None))
}

fn inspect_sloosh_path(
    hostname: &str,
    port: u16,
    observed: &PublicKey,
    path: &Path,
) -> Result<PathTrustState, SshError> {
    let contents = read_bounded(path)?;
    let keys = known_host_keys_from_contents(hostname, port, &contents)?;
    Ok(classify_known_keys(
        observed,
        &keys,
        Some((&contents, hostname, port)),
    ))
}

fn classify_known_keys(
    observed: &PublicKey,
    keys: &[(usize, PublicKey)],
    sloosh_line: Option<(&str, &str, u16)>,
) -> PathTrustState {
    if keys.iter().any(|(_, stored)| stored == observed) {
        return PathTrustState::Trusted;
    }
    let Some((line, stored)) = keys.first() else {
        return PathTrustState::Missing;
    };
    let replaceable = keys.len() == 1
        && sloosh_line.is_some_and(|(contents, hostname, port)| {
            plain_target_line(contents, hostname, port, *line)
        });
    PathTrustState::Changed {
        stored_fingerprint: stored.fingerprint(HashAlg::Sha256).to_string(),
        replaceable,
    }
}

fn known_host_keys_from_contents(
    hostname: &str,
    port: u16,
    contents: &str,
) -> Result<Vec<(usize, PublicKey)>, SshError> {
    let target = target_field(hostname, port);
    let mut matches = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut fields = trimmed.split_whitespace();
        let Some(hosts) = fields.next() else {
            continue;
        };
        let _algorithm = fields.next();
        let Some(encoded) = fields.next() else {
            continue;
        };
        if matches_host(&target, hosts) {
            matches.push((index + 1, russh::keys::parse_public_key_base64(encoded)?));
        }
    }
    Ok(matches)
}

fn matches_host(target: &str, patterns: &str) -> bool {
    patterns.split(',').any(|pattern| {
        if let Some(encoded) = pattern.strip_prefix("|1|") {
            let mut parts = encoded.split('|');
            let Some(Ok(salt)) = parts.next().map(|part| BASE64_MIME.decode(part.as_bytes()))
            else {
                return false;
            };
            let Some(Ok(hash)) = parts.next().map(|part| BASE64_MIME.decode(part.as_bytes()))
            else {
                return false;
            };
            Hmac::<Sha1>::new_from_slice(&salt).is_ok_and(|mut hmac| {
                hmac.update(target.as_bytes());
                hmac.verify_slice(&hash).is_ok()
            })
        } else {
            pattern == target
        }
    })
}

fn plain_target_line(contents: &str, hostname: &str, port: u16, line_number: usize) -> bool {
    let expected = if port == 22 {
        hostname.to_string()
    } else {
        format!("[{hostname}]:{port}")
    };
    contents
        .lines()
        .nth(line_number.saturating_sub(1))
        .and_then(|line| line.split_whitespace().next())
        .is_some_and(|field| field == expected)
}

pub(super) fn commit_at_path(
    path: &Path,
    hostname: &str,
    port: u16,
    observed: &PublicKey,
    mutation: KnownHostMutation<'_>,
) -> Result<(), SshError> {
    prepare_parent(path)?;
    let _lock = KnownHostsLock::acquire(path)?;
    let contents = read_bounded(path)?;
    let target = target_field(hostname, port);
    let encoded = observed
        .to_openssh()
        .map_err(|_| SshError::KnownHosts(russh::keys::Error::CouldNotReadKey))?;
    let replacement = format!("{target} {encoded}\n");
    let mut lines = contents
        .split_inclusive('\n')
        .map(ToOwned::to_owned)
        .collect::<Vec<String>>();
    if !contents.is_empty() && !contents.ends_with('\n') && lines.is_empty() {
        lines.push(contents.clone());
    }
    let existing = known_host_keys_from_contents(hostname, port, &contents)?;

    match mutation {
        KnownHostMutation::Add => {
            if !existing.is_empty() {
                return Err(SshError::HostKeyStateChanged);
            }
        }
        KnownHostMutation::Replace { stored_fingerprint } => {
            let [(line, stored)] = existing.as_slice() else {
                return if existing.is_empty() {
                    Err(SshError::HostKeyStateChanged)
                } else {
                    Err(SshError::HostKeyNotReplaceable)
                };
            };
            if !plain_target_line(&contents, hostname, port, *line) {
                return Err(SshError::HostKeyNotReplaceable);
            }
            if stored.fingerprint(HashAlg::Sha256).to_string() != stored_fingerprint {
                return Err(SshError::HostKeyStateChanged);
            }
            lines.remove(line.saturating_sub(1));
        }
    }

    let mut updated = lines.concat();
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&replacement);
    write_atomic(path, updated.as_bytes())
}

fn target_field(hostname: &str, port: u16) -> String {
    if port == 22 {
        hostname.to_string()
    } else {
        format!("[{hostname}]:{port}")
    }
}

fn prepare_parent(path: &Path) -> Result<(), SshError> {
    let Some(parent) = path.parent() else {
        return Err(SshError::UnsafeKnownHosts {
            reason: "known_hosts path has no parent directory",
        });
    };
    if parent == sloosh_home() {
        ensure_private_dir(parent).map_err(|error| {
            SshError::KnownHosts(russh::keys::Error::IO(std::io::Error::other(error)))
        })?;
    } else {
        std::fs::create_dir_all(parent)
            .map_err(|error| SshError::KnownHosts(russh::keys::Error::IO(error)))?;
    }
    Ok(())
}

struct KnownHostsLock {
    file: File,
}

impl KnownHostsLock {
    fn acquire(path: &Path) -> Result<Self, SshError> {
        let lock_path = path.with_extension("lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&lock_path)
            .map_err(|error| SshError::KnownHosts(russh::keys::Error::IO(error)))?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| SshError::KnownHosts(russh::keys::Error::IO(error)))?;
        // SAFETY: flock operates on this owned, live file descriptor. LOCK_EX
        // blocks only cooperating Sloosh writers and does not outlive `file`.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if result != 0 {
            return Err(SshError::KnownHosts(russh::keys::Error::IO(
                std::io::Error::last_os_error(),
            )));
        }
        Ok(Self { file })
    }
}

impl Drop for KnownHostsLock {
    fn drop(&mut self) {
        // SAFETY: descriptor remains valid for the duration of this call.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

use std::os::fd::AsRawFd as _;

fn read_bounded(path: &Path) -> Result<String, SshError> {
    let input = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(input) => input,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(SshError::KnownHosts(russh::keys::Error::IO(error))),
    };
    let metadata = input
        .metadata()
        .map_err(|error| SshError::KnownHosts(russh::keys::Error::IO(error)))?;
    if !metadata.is_file() {
        return Err(SshError::UnsafeKnownHosts {
            reason: "target is not a regular file",
        });
    }
    // SAFETY: geteuid has no arguments and only reads process credentials.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid {
        return Err(SshError::UnsafeKnownHosts {
            reason: "target is owned by another user",
        });
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SshError::UnsafeKnownHosts {
            reason: "target is readable or writable by group/other",
        });
    }
    if metadata.len() > MAX_KNOWN_HOSTS_BYTES {
        return Err(SshError::KnownHostsTooLarge);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    input
        .take(MAX_KNOWN_HOSTS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| SshError::KnownHosts(russh::keys::Error::IO(error)))?;
    if bytes.len() as u64 > MAX_KNOWN_HOSTS_BYTES {
        return Err(SshError::KnownHostsTooLarge);
    }
    String::from_utf8(bytes).map_err(|_| SshError::UnsafeKnownHosts {
        reason: "target is not valid UTF-8",
    })
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), SshError> {
    let parent = path.parent().ok_or(SshError::UnsafeKnownHosts {
        reason: "known_hosts path has no parent directory",
    })?;
    let mut random = [0_u8; 8];
    rand::rng().fill_bytes(&mut random);
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let temporary = PathBuf::from(format!(
        "{}.tmp-{}-{suffix}",
        path.display(),
        std::process::id()
    ));
    let result = (|| -> Result<(), SshError> {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .map_err(|error| SshError::KnownHosts(russh::keys::Error::IO(error)))?;
        output
            .write_all(bytes)
            .and_then(|()| output.sync_all())
            .map_err(|error| SshError::KnownHosts(russh::keys::Error::IO(error)))?;
        drop(output);
        std::fs::rename(&temporary, path)
            .map_err(|error| SshError::KnownHosts(russh::keys::Error::IO(error)))?;
        if let Err(error) = File::open(parent).and_then(|directory| directory.sync_all()) {
            tracing::warn!(
                error = %error,
                "known_hosts rename committed, but parent directory sync failed"
            );
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const TEST_KEY_A: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";
    const TEST_KEY_B: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X";
    const TEST_KEY_ECDSA: &str = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHwf2HMM5TRXvo2SQJjsNkiDD5KqiiNjrGVv3UUh+mMT5RHxiRtOnlqvjhQtBq0VpmpCV/PwUdhOig4vkbqAcEc=";

    struct Fixture {
        root: PathBuf,
        openssh: PathBuf,
        sloosh: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after unix epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "sloosh-known-host-state-{tag}-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir_all(&root).expect("create fixture");
            Self {
                openssh: root.join("openssh"),
                sloosh: root.join("sloosh"),
                root,
            }
        }

        fn write(&self, openssh_key: Option<&str>, sloosh_key: Option<&str>) {
            let line = |key: &str| format!("example.com ssh-ed25519 {key}\n");
            std::fs::write(&self.openssh, openssh_key.map(line).unwrap_or_default())
                .expect("write OpenSSH fixture");
            std::fs::write(&self.sloosh, sloosh_key.map(line).unwrap_or_default())
                .expect("write Sloosh fixture");
            std::fs::set_permissions(&self.sloosh, std::fs::Permissions::from_mode(0o600))
                .expect("secure Sloosh fixture");
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn test_public_key(encoded: &str) -> PublicKey {
        russh::keys::parse_public_key_base64(encoded).expect("valid test public key")
    }

    #[test]
    fn missing_key_is_reported_as_unknown() {
        let fixture = Fixture::new("unknown");

        let state = inspect_at_paths(
            "example.com",
            22,
            &test_public_key(TEST_KEY_A),
            &fixture.openssh,
            &fixture.sloosh,
        )
        .expect("missing files are an empty trust store");

        assert_eq!(state, HostKeyTrustState::Unknown);
    }

    #[test]
    fn matching_key_in_either_store_is_trusted() {
        let fixture = Fixture::new("trusted");
        fixture.write(Some(TEST_KEY_A), None);
        assert_eq!(
            inspect_at_paths(
                "example.com",
                22,
                &test_public_key(TEST_KEY_A),
                &fixture.openssh,
                &fixture.sloosh,
            )
            .unwrap(),
            HostKeyTrustState::Trusted
        );

        fixture.write(None, Some(TEST_KEY_A));
        assert_eq!(
            inspect_at_paths(
                "example.com",
                22,
                &test_public_key(TEST_KEY_A),
                &fixture.openssh,
                &fixture.sloosh,
            )
            .unwrap(),
            HostKeyTrustState::Trusted
        );
    }

    #[test]
    fn sloosh_mismatch_is_replaceable_but_openssh_mismatch_is_external() {
        let fixture = Fixture::new("changed");
        let observed = test_public_key(TEST_KEY_A);
        let old_fingerprint = test_public_key(TEST_KEY_B)
            .fingerprint(HashAlg::Sha256)
            .to_string();

        fixture.write(None, Some(TEST_KEY_B));
        assert_eq!(
            inspect_at_paths(
                "example.com",
                22,
                &observed,
                &fixture.openssh,
                &fixture.sloosh,
            )
            .unwrap(),
            HostKeyTrustState::Changed {
                source: KnownHostSource::Sloosh,
                stored_fingerprint: old_fingerprint.clone(),
                replaceable: true,
            }
        );

        fixture.write(Some(TEST_KEY_B), Some(TEST_KEY_A));
        assert_eq!(
            inspect_at_paths(
                "example.com",
                22,
                &observed,
                &fixture.openssh,
                &fixture.sloosh,
            )
            .unwrap(),
            HostKeyTrustState::Changed {
                source: KnownHostSource::OpenSsh,
                stored_fingerprint: old_fingerprint,
                replaceable: false,
            }
        );
    }

    #[test]
    fn algorithm_rotation_is_changed_and_can_replace_one_plain_sloosh_line() {
        let fixture = Fixture::new("algorithm-rotation");
        fixture.write(None, Some(TEST_KEY_A));
        let observed = test_public_key(TEST_KEY_ECDSA);
        let old_fingerprint = test_public_key(TEST_KEY_A)
            .fingerprint(HashAlg::Sha256)
            .to_string();

        assert_eq!(
            inspect_at_paths(
                "example.com",
                22,
                &observed,
                &fixture.openssh,
                &fixture.sloosh,
            )
            .unwrap(),
            HostKeyTrustState::Changed {
                source: KnownHostSource::Sloosh,
                stored_fingerprint: old_fingerprint.clone(),
                replaceable: true,
            }
        );

        commit_at_path(
            &fixture.sloosh,
            "example.com",
            22,
            &observed,
            KnownHostMutation::Replace {
                stored_fingerprint: &old_fingerprint,
            },
        )
        .unwrap();
        assert_eq!(
            inspect_at_paths(
                "example.com",
                22,
                &observed,
                &fixture.openssh,
                &fixture.sloosh,
            )
            .unwrap(),
            HostKeyTrustState::Trusted
        );
    }

    #[test]
    fn replacement_preserves_unrelated_lines_and_replaces_only_expected_key() {
        let fixture = Fixture::new("replace");
        let old = test_public_key(TEST_KEY_B);
        let observed = test_public_key(TEST_KEY_A);
        std::fs::write(
            &fixture.sloosh,
            format!(
                "# retained comment\nother.example ssh-ed25519 {TEST_KEY_B}\nexample.com {}\n",
                old.to_openssh().unwrap()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fixture.sloosh, std::fs::Permissions::from_mode(0o600)).unwrap();

        commit_at_path(
            &fixture.sloosh,
            "example.com",
            22,
            &observed,
            KnownHostMutation::Replace {
                stored_fingerprint: &old.fingerprint(HashAlg::Sha256).to_string(),
            },
        )
        .unwrap();

        let contents = std::fs::read_to_string(&fixture.sloosh).unwrap();
        assert!(contents.contains("# retained comment\n"));
        assert!(contents.contains(&format!("other.example ssh-ed25519 {TEST_KEY_B}\n")));
        assert!(!contents.contains(&format!("example.com {}\n", old.to_openssh().unwrap())));
        assert!(contents.contains(&format!("example.com {}\n", observed.to_openssh().unwrap())));
    }

    #[test]
    fn add_creates_a_private_file_and_preserves_existing_bytes() {
        let fixture = Fixture::new("add");
        std::fs::write(&fixture.sloosh, "# retained\n\n").unwrap();
        std::fs::set_permissions(&fixture.sloosh, std::fs::Permissions::from_mode(0o600)).unwrap();
        commit_at_path(
            &fixture.sloosh,
            "example.com",
            2222,
            &test_public_key(TEST_KEY_A),
            KnownHostMutation::Add,
        )
        .unwrap();

        let contents = std::fs::read_to_string(&fixture.sloosh).unwrap();
        assert!(contents.starts_with("# retained\n\n"));
        assert!(contents.contains(&format!(
            "[example.com]:2222 {}\n",
            test_public_key(TEST_KEY_A).to_openssh().unwrap()
        )));
        assert_eq!(
            std::fs::metadata(&fixture.sloosh)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn replace_rejects_a_stale_stored_fingerprint_without_writing() {
        let fixture = Fixture::new("stale");
        fixture.write(None, Some(TEST_KEY_B));
        let before = std::fs::read(&fixture.sloosh).unwrap();

        let error = commit_at_path(
            &fixture.sloosh,
            "example.com",
            22,
            &test_public_key(TEST_KEY_A),
            KnownHostMutation::Replace {
                stored_fingerprint: "SHA256:stale",
            },
        )
        .unwrap_err();

        assert!(matches!(error, SshError::HostKeyStateChanged));
        assert_eq!(std::fs::read(&fixture.sloosh).unwrap(), before);
    }

    #[test]
    fn unsafe_sloosh_files_are_rejected_during_preview() {
        let fixture = Fixture::new("unsafe");
        fixture.write(None, Some(TEST_KEY_A));
        std::fs::set_permissions(&fixture.sloosh, std::fs::Permissions::from_mode(0o644)).unwrap();

        let error = inspect_at_paths(
            "example.com",
            22,
            &test_public_key(TEST_KEY_A),
            &fixture.openssh,
            &fixture.sloosh,
        )
        .unwrap_err();

        assert!(matches!(error, SshError::UnsafeKnownHosts { .. }));
    }

    #[test]
    fn symlinked_sloosh_file_is_rejected_during_preview() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new("symlink");
        let target = fixture.root.join("target");
        std::fs::write(&target, format!("example.com ssh-ed25519 {TEST_KEY_A}\n")).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &fixture.sloosh).unwrap();

        let error = inspect_at_paths(
            "example.com",
            22,
            &test_public_key(TEST_KEY_A),
            &fixture.openssh,
            &fixture.sloosh,
        )
        .unwrap_err();

        assert!(matches!(error, SshError::KnownHosts(_)));
    }

    #[test]
    fn hashed_or_multi_host_sloosh_lines_are_never_replaceable() {
        let fixture = Fixture::new("non-plain");
        let target = "example.com";
        let salt = b"01234567890123456789";
        let mut hmac = Hmac::<Sha1>::new_from_slice(salt).unwrap();
        hmac.update(target.as_bytes());
        let hash = hmac.finalize().into_bytes();
        let hashed = format!("|1|{}|{}", BASE64.encode(salt), BASE64.encode(&hash));
        assert!(matches_host(target, &hashed));
        assert!(matches_host(target, &format!("{hashed},other.example")));
        std::fs::write(
            &fixture.sloosh,
            format!("{hashed},other.example ssh-ed25519 {TEST_KEY_B}\n"),
        )
        .unwrap();
        std::fs::set_permissions(&fixture.sloosh, std::fs::Permissions::from_mode(0o600)).unwrap();
        let fixture_contents = std::fs::read_to_string(&fixture.sloosh).unwrap();
        assert!(
            matches_host(target, fixture_contents.split_whitespace().next().unwrap()),
            "{fixture_contents:?}"
        );
        assert_eq!(
            known_host_keys_from_contents(target, 22, &fixture_contents)
                .unwrap()
                .len(),
            1
        );

        let state = inspect_at_paths(
            target,
            22,
            &test_public_key(TEST_KEY_A),
            &fixture.openssh,
            &fixture.sloosh,
        )
        .unwrap();

        assert!(
            matches!(
                state,
                HostKeyTrustState::Changed {
                    source: KnownHostSource::Sloosh,
                    replaceable: false,
                    ..
                }
            ),
            "{state:?}"
        );
    }
}
