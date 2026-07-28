//! Local authorization methods that approve a daemon-owned lease preview.

use crate::proto::SecretString;
use crate::transport::unix::{ensure_private_dir, sloosh_home};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use std::io::{self, Read as _, Write as _};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

const PIN_VERSION: u32 = 1;
const PIN_LENGTH: usize = 6;
const PIN_SALT_LENGTH: usize = 16;
const PIN_HASH_LENGTH: usize = 32;
const PIN_M_COST: u32 = 64 * 1024;
const PIN_T_COST: u32 = 3;
const PIN_P_COST: u32 = 1;
const MAX_PIN_FAILURES: u32 = 15;
const MAX_PIN_FILE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PinStatus {
    NotConfigured,
    Ready,
    Locked { remaining_secs: u64 },
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinVerify {
    Approved,
    Rejected { remaining_attempts: u32 },
    Locked { remaining_secs: u64 },
    Disabled,
}

#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("approval PIN must contain exactly six ASCII digits")]
    InvalidFormat,
    #[error("approval PIN is not configured")]
    NotConfigured,
    #[error("refusing unsafe approval PIN state file")]
    UnsafeFile,
    #[error("approval PIN state is corrupt or unsupported")]
    Corrupt,
    #[error("approval PIN state I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("approval PIN derivation failed")]
    Kdf,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct PinKdf {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct PinFile {
    version: u32,
    kdf: PinKdf,
    salt: String,
    hash: String,
    failed_attempts: u32,
    locked_until: u64,
    disabled: bool,
}

#[derive(Debug, Clone)]
pub struct PinStore {
    path: PathBuf,
    kdf: PinKdf,
}

impl PinStore {
    pub fn current_user() -> Self {
        Self {
            path: sloosh_home().join("approval-pin.json"),
            kdf: PinKdf {
                m_cost: PIN_M_COST,
                t_cost: PIN_T_COST,
                p_cost: PIN_P_COST,
            },
        }
    }

    #[cfg(all(test, unix))]
    fn for_test(path: PathBuf) -> Self {
        Self {
            path,
            kdf: PinKdf {
                m_cost: 8,
                t_cost: 1,
                p_cost: 1,
            },
        }
    }

    pub fn status(&self) -> Result<PinStatus, PinError> {
        self.status_at(unix_time())
    }

    fn status_at(&self, now: u64) -> Result<PinStatus, PinError> {
        let Some(file) = self.read()? else {
            return Ok(PinStatus::NotConfigured);
        };
        if file.disabled {
            return Ok(PinStatus::Disabled);
        }
        if file.locked_until > now {
            return Ok(PinStatus::Locked {
                remaining_secs: file.locked_until - now,
            });
        }
        Ok(PinStatus::Ready)
    }

    pub fn enroll(&self, pin: &SecretString) -> Result<(), PinError> {
        validate_pin(pin)?;
        self.refuse_symlink()?;
        let mut salt = [0u8; PIN_SALT_LENGTH];
        rand::rng().fill_bytes(&mut salt);
        let hash = derive_pin(pin, &salt, self.kdf)?;
        let file = PinFile {
            version: PIN_VERSION,
            kdf: self.kdf,
            salt: hex_encode(&salt),
            hash: hex_encode(hash.as_ref()),
            failed_attempts: 0,
            locked_until: 0,
            disabled: false,
        };
        self.write(&file)
    }

    pub fn verify(&self, pin: &SecretString) -> Result<PinVerify, PinError> {
        self.verify_at(pin, unix_time())
    }

    fn verify_at(&self, pin: &SecretString, now: u64) -> Result<PinVerify, PinError> {
        validate_pin(pin)?;
        let mut file = self.read()?.ok_or(PinError::NotConfigured)?;
        if file.disabled {
            return Ok(PinVerify::Disabled);
        }
        if file.locked_until > now {
            return Ok(PinVerify::Locked {
                remaining_secs: file.locked_until - now,
            });
        }
        let salt = hex_decode::<PIN_SALT_LENGTH>(&file.salt)?;
        let expected = hex_decode::<PIN_HASH_LENGTH>(&file.hash)?;
        let actual = derive_pin(pin, &salt, file.kdf)?;
        if bool::from(actual.as_ref().ct_eq(&expected)) {
            file.failed_attempts = 0;
            file.locked_until = 0;
            self.write(&file)?;
            return Ok(PinVerify::Approved);
        }

        file.failed_attempts = file.failed_attempts.saturating_add(1);
        if file.failed_attempts >= MAX_PIN_FAILURES {
            file.disabled = true;
            file.locked_until = 0;
            self.write(&file)?;
            return Ok(PinVerify::Disabled);
        }
        let delay = match file.failed_attempts {
            5 => 30,
            10 => 2 * 60,
            14 => 10 * 60,
            _ => 0,
        };
        if delay > 0 {
            file.locked_until = now.saturating_add(delay);
        }
        self.write(&file)?;
        if delay > 0 {
            Ok(PinVerify::Locked {
                remaining_secs: delay,
            })
        } else {
            Ok(PinVerify::Rejected {
                remaining_attempts: MAX_PIN_FAILURES - file.failed_attempts,
            })
        }
    }

    pub fn remove(&self) -> Result<(), PinError> {
        self.refuse_symlink()?;
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn refuse_symlink(&self) -> Result<(), PinError> {
        match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.file_type().is_symlink() => Err(PinError::UnsafeFile),
            Ok(metadata) if !metadata.is_file() => Err(PinError::UnsafeFile),
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn read(&self) -> Result<Option<PinFile>, PinError> {
        self.refuse_symlink()?;
        let file = match crate::platform_fs::open_private_read(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        if metadata.len() > MAX_PIN_FILE_BYTES {
            return Err(PinError::UnsafeFile);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_PIN_FILE_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_PIN_FILE_BYTES {
            return Err(PinError::UnsafeFile);
        }
        let decoded: PinFile = serde_json::from_slice(&bytes).map_err(|_| PinError::Corrupt)?;
        validate_file(&decoded)?;
        Ok(Some(decoded))
    }

    fn write(&self, state: &PinFile) -> Result<(), PinError> {
        self.refuse_symlink()?;
        if let Some(parent) = self.path.parent() {
            if parent == sloosh_home() {
                ensure_private_dir(parent).map_err(|error| io::Error::other(error.to_string()))?;
            } else {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut random = [0u8; 8];
        rand::rng().fill_bytes(&mut random);
        let temp = self.path.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            hex_encode(&random)
        ));
        let encoded = serde_json::to_vec_pretty(state).map_err(|_| PinError::Corrupt)?;
        let result = (|| -> Result<(), PinError> {
            let mut output = crate::platform_fs::create_new_private(&temp)?;
            output.write_all(&encoded)?;
            output.sync_all()?;
            drop(output);
            std::fs::rename(&temp, &self.path)?;
            crate::platform_fs::harden_path(&self.path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }
}

fn validate_pin(pin: &SecretString) -> Result<(), PinError> {
    let bytes = pin.expose_secret().as_bytes();
    if bytes.len() == PIN_LENGTH && bytes.iter().all(u8::is_ascii_digit) {
        Ok(())
    } else {
        Err(PinError::InvalidFormat)
    }
}

fn validate_file(file: &PinFile) -> Result<(), PinError> {
    if file.version != PIN_VERSION
        || file.failed_attempts > MAX_PIN_FAILURES
        || file.kdf.m_cost < 8
        || file.kdf.m_cost > 256 * 1024
        || file.kdf.t_cost == 0
        || file.kdf.t_cost > 10
        || file.kdf.p_cost == 0
        || file.kdf.p_cost > 8
    {
        return Err(PinError::Corrupt);
    }
    hex_decode::<PIN_SALT_LENGTH>(&file.salt)?;
    hex_decode::<PIN_HASH_LENGTH>(&file.hash)?;
    Ok(())
}

fn derive_pin(
    pin: &SecretString,
    salt: &[u8; PIN_SALT_LENGTH],
    kdf: PinKdf,
) -> Result<Zeroizing<[u8; PIN_HASH_LENGTH]>, PinError> {
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(PIN_HASH_LENGTH))
        .map_err(|_| PinError::Kdf)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0u8; PIN_HASH_LENGTH]);
    argon2
        .hash_password_into(pin.expose_secret().as_bytes(), salt, output.as_mut())
        .map_err(|_| PinError::Kdf)?;
    Ok(output)
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_decode<const N: usize>(value: &str) -> Result<[u8; N], PinError> {
    if value.len() != N * 2 {
        return Err(PinError::Corrupt);
    }
    let mut output = [0u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(PinError::Corrupt)?;
        let low = hex_nibble(pair[1]).ok_or(PinError::Corrupt)?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::proto::SecretString;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_path(tag: &str) -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "sloosh-pin-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn pin(value: &str) -> SecretString {
        SecretString::new(value.to_owned())
    }

    #[test]
    fn enrollment_round_trip_is_private_and_success_resets_failures() {
        let path = temp_path("roundtrip");
        let store = PinStore::for_test(path.clone());
        store.enroll(&pin("482731")).unwrap();
        assert_eq!(store.status_at(100).unwrap(), PinStatus::Ready);
        assert!(matches!(
            store.verify_at(&pin("000000"), 100).unwrap(),
            PinVerify::Rejected {
                remaining_attempts: 14
            }
        ));
        assert_eq!(
            store.verify_at(&pin("482731"), 100).unwrap(),
            PinVerify::Approved
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn lockout_and_disable_survive_store_recreation() {
        let path = temp_path("lockout");
        let store = PinStore::for_test(path.clone());
        store.enroll(&pin("482731")).unwrap();
        for attempt in 0..4 {
            assert!(matches!(
                store.verify_at(&pin("000000"), 100 + attempt).unwrap(),
                PinVerify::Rejected { .. }
            ));
        }
        assert_eq!(
            store.verify_at(&pin("000000"), 104).unwrap(),
            PinVerify::Locked { remaining_secs: 30 }
        );
        let reopened = PinStore::for_test(path.clone());
        assert_eq!(
            reopened.status_at(105).unwrap(),
            PinStatus::Locked { remaining_secs: 29 }
        );

        let mut now = 1_000;
        for _ in 5..15 {
            let result = reopened.verify_at(&pin("000000"), now).unwrap();
            now += match result {
                PinVerify::Locked { remaining_secs } => remaining_secs + 1,
                _ => 1,
            };
        }
        assert_eq!(reopened.status_at(now).unwrap(), PinStatus::Disabled);
        assert_eq!(
            reopened.verify_at(&pin("482731"), now).unwrap(),
            PinVerify::Disabled
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn enrollment_requires_exactly_six_ascii_digits() {
        let path = temp_path("format");
        let store = PinStore::for_test(path);
        for invalid in ["12345", "1234567", "12 456", "１２３４５６"] {
            assert!(matches!(
                store.enroll(&pin(invalid)),
                Err(PinError::InvalidFormat)
            ));
        }
    }

    #[test]
    fn state_file_symlink_is_refused() {
        let target = temp_path("target");
        let link = temp_path("link");
        std::fs::write(&target, b"outside").unwrap();
        symlink(&target, &link).unwrap();
        let store = PinStore::for_test(link.clone());
        assert!(matches!(
            store.enroll(&pin("482731")),
            Err(PinError::UnsafeFile)
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"outside");
        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_file(target);
    }
}
