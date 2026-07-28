use crate::transport::unix::{ensure_private_dir, sloosh_home};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use std::io::{self, Read as _, Write as _};
use std::path::PathBuf;
use std::time::Duration;

const SETTINGS_VERSION: u32 = 1;
const MAX_SETTINGS_BYTES: u64 = 4 * 1024;
pub const SUPPORTED_TIMEOUT_MINUTES: [u16; 4] = [1, 5, 15, 30];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultTimeout(u16);

impl VaultTimeout {
    pub const fn minimum() -> Self {
        Self(SUPPORTED_TIMEOUT_MINUTES[0])
    }

    pub const fn minutes(self) -> u16 {
        self.0
    }

    pub const fn duration(self) -> Duration {
        Duration::from_secs(self.0 as u64 * 60)
    }
}

impl Default for VaultTimeout {
    fn default() -> Self {
        Self(15)
    }
}

impl TryFrom<u16> for VaultTimeout {
    type Error = VaultSettingsError;

    fn try_from(minutes: u16) -> Result<Self, Self::Error> {
        if SUPPORTED_TIMEOUT_MINUTES.contains(&minutes) {
            Ok(Self(minutes))
        } else {
            Err(VaultSettingsError::UnsupportedTimeout(minutes))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VaultSettingsError {
    #[error("vault timeout must be one of 1, 5, 15, or 30 minutes (got {0})")]
    UnsupportedTimeout(u16),
    #[error("refusing unsafe vault settings file")]
    UnsafeFile,
    #[error("vault settings file is corrupt or unsupported")]
    Corrupt,
    #[error("vault settings I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Serialize, Deserialize)]
struct SettingsFile {
    version: u32,
    idle_timeout_minutes: u16,
}

#[derive(Debug, Clone)]
pub struct VaultSettingsStore {
    path: PathBuf,
}

impl VaultSettingsStore {
    pub fn current_user() -> Self {
        Self {
            path: sloosh_home().join("vault-settings.json"),
        }
    }

    #[cfg(all(test, unix))]
    fn for_test(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn load(&self) -> Result<VaultTimeout, VaultSettingsError> {
        self.refuse_unsafe_target()?;
        let input = match crate::platform_fs::open_private_read(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(VaultTimeout::default());
            }
            Err(error) => return Err(error.into()),
        };
        let metadata = input.metadata()?;
        if metadata.len() > MAX_SETTINGS_BYTES {
            return Err(VaultSettingsError::UnsafeFile);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        input.take(MAX_SETTINGS_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_SETTINGS_BYTES {
            return Err(VaultSettingsError::UnsafeFile);
        }
        let file: SettingsFile =
            serde_json::from_slice(&bytes).map_err(|_| VaultSettingsError::Corrupt)?;
        if file.version != SETTINGS_VERSION {
            return Err(VaultSettingsError::Corrupt);
        }
        VaultTimeout::try_from(file.idle_timeout_minutes).map_err(|_| VaultSettingsError::Corrupt)
    }

    pub fn save(&self, timeout: VaultTimeout) -> Result<(), VaultSettingsError> {
        self.refuse_unsafe_target()?;
        if let Some(parent) = self.path.parent() {
            if parent == sloosh_home() {
                ensure_private_dir(parent).map_err(|error| io::Error::other(error.to_string()))?;
            } else {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = SettingsFile {
            version: SETTINGS_VERSION,
            idle_timeout_minutes: timeout.minutes(),
        };
        let encoded = serde_json::to_vec_pretty(&file).map_err(|_| VaultSettingsError::Corrupt)?;
        let mut random = [0_u8; 8];
        rand::rng().fill_bytes(&mut random);
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let temporary = self
            .path
            .with_extension(format!("tmp-{}-{suffix}", std::process::id()));
        let result = (|| -> Result<(), VaultSettingsError> {
            let mut output = crate::platform_fs::create_new_private(&temporary)?;
            output.write_all(&encoded)?;
            output.sync_all()?;
            drop(output);
            std::fs::rename(&temporary, &self.path)?;
            crate::platform_fs::harden_path(&self.path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }

    fn refuse_unsafe_target(&self) -> Result<(), VaultSettingsError> {
        match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                Err(VaultSettingsError::UnsafeFile)
            }
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temporary_path(tag: &str) -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "sloosh-vault-settings-{tag}-{}-{}.json",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn only_supported_timeout_choices_are_accepted() {
        for minutes in [1_u16, 5, 15, 30] {
            assert_eq!(VaultTimeout::try_from(minutes).unwrap().minutes(), minutes);
        }
        for minutes in [0_u16, 2, 60] {
            assert!(VaultTimeout::try_from(minutes).is_err());
        }
    }

    #[test]
    fn missing_settings_use_fifteen_minutes() {
        let path = temporary_path("missing");
        let store = VaultSettingsStore::for_test(path);
        assert_eq!(store.load().unwrap(), VaultTimeout::default());
        assert_eq!(store.load().unwrap().minutes(), 15);
    }

    #[test]
    fn settings_round_trip_with_private_permissions() {
        let path = temporary_path("round-trip");
        let store = VaultSettingsStore::for_test(path.clone());
        store.save(VaultTimeout::try_from(5).unwrap()).unwrap();

        assert_eq!(store.load().unwrap().minutes(), 5);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn settings_refuse_a_symlink_target() {
        let target = temporary_path("target");
        let link = temporary_path("link");
        std::fs::write(&target, b"unchanged").unwrap();
        symlink(&target, &link).unwrap();
        let store = VaultSettingsStore::for_test(link.clone());

        assert!(matches!(
            store.save(VaultTimeout::default()),
            Err(VaultSettingsError::UnsafeFile)
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(target).unwrap();
    }
}
