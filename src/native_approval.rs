//! Native human-approval adapter.
//!
//! Rust owns policy and lease activation. Bundled macOS helper owns
//! Keychain/Touch ID UI and returns a short-lived vault password only over
//! anonymous pipes inherited from daemon.

use crate::daemon::{lease, ssh, vault};
use crate::local_approval::{PinError, PinStatus, PinStore, PinVerify};
use crate::proto::{LeaseActivatedInfo, LeaseRequestSummary, SecretString};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use zeroize::Zeroizing;

const MAX_HELPER_MESSAGE_BYTES: usize = 64 * 1024;
const HELPER_INTERACTION_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const HELPER_EXIT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum NativeApprovalError {
    #[error("native approval helper is not installed")]
    Unavailable,
    #[error("native approval is not enrolled; run `sloosh init` in a terminal")]
    NotEnrolled,
    #[error("native approval was cancelled")]
    Cancelled,
    #[error("one or more SSH host keys still need terminal confirmation")]
    HostKeyConfirmationRequired,
    #[error("native approval helper failed: {0}")]
    Helper(String),
    #[error("native approval helper I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("native approval helper timed out")]
    TimedOut,
    #[error("native approval helper returned invalid data: {0}")]
    InvalidData(String),
    #[error(transparent)]
    Vault(#[from] vault::VaultError),
    #[error(transparent)]
    Lease(#[from] lease::LeaseError),
    #[error(transparent)]
    Pin(#[from] PinError),
    #[error("wrong approval PIN ({remaining} attempt(s) remain)")]
    WrongPin { remaining: u32 },
    #[error("approval PIN is locked for {remaining_secs} seconds")]
    PinLocked { remaining_secs: u64 },
    #[error("approval PIN was disabled after too many failed attempts; re-enable it in Sloosh")]
    PinDisabled,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HelperRequest<'a> {
    Status,
    Enroll {
        master_password: &'a str,
    },
    Begin {
        request_id: &'a str,
        hosts: &'a [String],
        anchor_name: Option<&'a str>,
        anchor_pid: u32,
    },
    Confirm {
        hosts: &'a [String],
        allow_pin: bool,
    },
    PromptMasterPassword {
        purpose: &'a str,
        confirm: bool,
    },
    StorePinCredential {
        master_password: &'a str,
    },
    PromptPin,
    RemovePinCredential,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HelperResponse {
    Enrolled,
    Unlocked {
        master_password: SecretString,
    },
    Approved,
    MasterPasswordEntered {
        master_password: SecretString,
    },
    PinEntered {
        pin: SecretString,
    },
    PinCredentialStored,
    PinCredentialRemoved,
    ApprovalStatus {
        touch_id_enrolled: bool,
        pin_credential_stored: bool,
    },
    Error {
        code: String,
        message: String,
    },
}

struct HelperProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl HelperProcess {
    async fn spawn() -> Result<Self, NativeApprovalError> {
        let path = helper_path().ok_or(NativeApprovalError::Unavailable)?;
        validate_helper(&path)?;
        let mut child = Command::new(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let stdin = child.stdin.take().ok_or_else(|| {
            NativeApprovalError::InvalidData("helper stdin was not created".into())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            NativeApprovalError::InvalidData("helper stdout was not created".into())
        })?;
        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    async fn exchange(
        &mut self,
        request: &HelperRequest<'_>,
    ) -> Result<HelperResponse, NativeApprovalError> {
        let mut encoded = serde_json::to_vec(request)
            .map_err(|error| NativeApprovalError::InvalidData(error.to_string()))?;
        if encoded.len() + 1 > MAX_HELPER_MESSAGE_BYTES {
            return Err(NativeApprovalError::InvalidData(
                "request exceeds helper message limit".into(),
            ));
        }
        encoded.push(b'\n');
        self.stdin.write_all(&encoded).await?;
        self.stdin.flush().await?;
        encoded.fill(0);

        let mut line = Zeroizing::new(String::new());
        let read = tokio::time::timeout(
            HELPER_INTERACTION_TIMEOUT,
            (&mut self.stdout)
                .take((MAX_HELPER_MESSAGE_BYTES + 1) as u64)
                .read_line(&mut line),
        )
        .await
        .map_err(|_| NativeApprovalError::TimedOut)??;
        if read == 0 {
            return Err(NativeApprovalError::InvalidData(
                "helper closed without a response".into(),
            ));
        }
        if read > MAX_HELPER_MESSAGE_BYTES || !line.ends_with('\n') {
            return Err(NativeApprovalError::InvalidData(
                "helper response exceeds limit or lacks newline".into(),
            ));
        }
        serde_json::from_str(&line)
            .map_err(|error| NativeApprovalError::InvalidData(error.to_string()))
    }

    async fn finish(mut self) -> Result<(), NativeApprovalError> {
        drop(self.stdin);
        let status = tokio::time::timeout(HELPER_EXIT_TIMEOUT, self.child.wait())
            .await
            .map_err(|_| NativeApprovalError::TimedOut)??;
        if status.success() {
            Ok(())
        } else {
            Err(NativeApprovalError::Helper(format!(
                "exited with status {status}"
            )))
        }
    }
}

fn map_helper_error(code: String, message: String) -> NativeApprovalError {
    match code.as_str() {
        "not_enrolled" => NativeApprovalError::NotEnrolled,
        "cancelled" => NativeApprovalError::Cancelled,
        _ => NativeApprovalError::Helper(message),
    }
}

pub async fn enroll(master_password: &SecretString) -> Result<(), NativeApprovalError> {
    vault::unlock(master_password.expose_secret().as_bytes())?;
    let mut helper = HelperProcess::spawn().await?;
    match helper
        .exchange(&HelperRequest::Enroll {
            master_password: master_password.expose_secret(),
        })
        .await?
    {
        HelperResponse::Enrolled => helper.finish().await,
        HelperResponse::Error { code, message } => Err(map_helper_error(code, message)),
        _ => Err(NativeApprovalError::InvalidData(
            "unexpected enrollment response".into(),
        )),
    }
}

pub fn is_available() -> bool {
    helper_path()
        .as_deref()
        .is_some_and(|path| validate_helper(path).is_ok())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeApprovalStatus {
    pub touch_id_enrolled: bool,
    pub pin_credential_stored: bool,
}

pub async fn status() -> Result<NativeApprovalStatus, NativeApprovalError> {
    let mut helper = HelperProcess::spawn().await?;
    match helper.exchange(&HelperRequest::Status).await? {
        HelperResponse::ApprovalStatus {
            touch_id_enrolled,
            pin_credential_stored,
        } => {
            helper.finish().await?;
            Ok(NativeApprovalStatus {
                touch_id_enrolled,
                pin_credential_stored,
            })
        }
        HelperResponse::Error { code, message } => Err(map_helper_error(code, message)),
        _ => Err(NativeApprovalError::InvalidData(
            "unexpected native approval status response".into(),
        )),
    }
}

pub async fn prompt_master_password(
    purpose: &str,
    confirm: bool,
) -> Result<SecretString, NativeApprovalError> {
    let mut helper = HelperProcess::spawn().await?;
    let response = helper
        .exchange(&HelperRequest::PromptMasterPassword { purpose, confirm })
        .await?;
    match response {
        HelperResponse::MasterPasswordEntered { master_password } => {
            helper.finish().await?;
            Ok(master_password)
        }
        HelperResponse::Error { code, message } => Err(map_helper_error(code, message)),
        _ => Err(NativeApprovalError::InvalidData(
            "unexpected master password response".into(),
        )),
    }
}

pub async fn prompt_pin() -> Result<SecretString, NativeApprovalError> {
    let mut helper = HelperProcess::spawn().await?;
    let response = helper.exchange(&HelperRequest::PromptPin).await?;
    match response {
        HelperResponse::PinEntered { pin } => {
            helper.finish().await?;
            Ok(pin)
        }
        HelperResponse::Error { code, message } => Err(map_helper_error(code, message)),
        _ => Err(NativeApprovalError::InvalidData(
            "unexpected approval PIN response".into(),
        )),
    }
}

pub async fn store_pin_credential(
    master_password: &SecretString,
) -> Result<(), NativeApprovalError> {
    let mut helper = HelperProcess::spawn().await?;
    match helper
        .exchange(&HelperRequest::StorePinCredential {
            master_password: master_password.expose_secret(),
        })
        .await?
    {
        HelperResponse::PinCredentialStored => helper.finish().await,
        HelperResponse::Error { code, message } => Err(map_helper_error(code, message)),
        _ => Err(NativeApprovalError::InvalidData(
            "unexpected approval PIN credential response".into(),
        )),
    }
}

pub async fn remove_pin_credential() -> Result<(), NativeApprovalError> {
    let mut helper = HelperProcess::spawn().await?;
    match helper.exchange(&HelperRequest::RemovePinCredential).await? {
        HelperResponse::PinCredentialRemoved => helper.finish().await,
        HelperResponse::Error { code, message } => Err(map_helper_error(code, message)),
        _ => Err(NativeApprovalError::InvalidData(
            "unexpected approval PIN removal response".into(),
        )),
    }
}

pub async fn try_approve(
    info: &LeaseRequestSummary,
) -> Result<LeaseActivatedInfo, NativeApprovalError> {
    let mut helper = HelperProcess::spawn().await?;
    let master_password = match helper
        .exchange(&HelperRequest::Begin {
            request_id: &info.id,
            hosts: &info.hosts,
            anchor_name: info.anchor_name.as_deref(),
            anchor_pid: info.anchor_pid,
        })
        .await?
    {
        HelperResponse::Unlocked { master_password } => master_password,
        HelperResponse::Error { code, message } => return Err(map_helper_error(code, message)),
        _ => {
            return Err(NativeApprovalError::InvalidData(
                "unexpected unlock response".into(),
            ));
        }
    };

    let approved_hosts =
        lease::preview_native_approval(&info.id, master_password.expose_secret().as_bytes())
            .await?;
    for host in &approved_hosts {
        let (hostname, port) = ssh::resolve_endpoint(host).await;
        if !ssh::host_has_known_key(&hostname, port) {
            lease::discard_native_preview().await;
            return Err(NativeApprovalError::HostKeyConfirmationRequired);
        }
    }
    let pin_store = PinStore::current_user();
    let allow_pin = match pin_store.status() {
        Ok(status) => matches!(status, PinStatus::Ready),
        Err(error) => {
            lease::discard_native_preview().await;
            return Err(error.into());
        }
    };
    let confirmation = helper
        .exchange(&HelperRequest::Confirm {
            hosts: &approved_hosts,
            allow_pin,
        })
        .await;
    let entered_pin = match confirmation {
        Ok(HelperResponse::Approved) => None,
        Ok(HelperResponse::PinEntered { pin }) => Some(pin),
        Ok(HelperResponse::Error { code, message }) => {
            lease::discard_native_preview().await;
            return Err(map_helper_error(code, message));
        }
        Ok(_) => {
            lease::discard_native_preview().await;
            return Err(NativeApprovalError::InvalidData(
                "unexpected confirmation response".into(),
            ));
        }
        Err(error) => {
            lease::discard_native_preview().await;
            return Err(error);
        }
    };
    if let Err(error) = helper.finish().await {
        lease::discard_native_preview().await;
        return Err(error);
    }
    if let Some(pin) = entered_pin {
        let verification = match pin_store.verify(&pin) {
            Ok(verification) => verification,
            Err(error) => {
                lease::discard_native_preview().await;
                return Err(error.into());
            }
        };
        match verification {
            PinVerify::Approved => {}
            PinVerify::Rejected { remaining_attempts } => {
                lease::discard_native_preview().await;
                return Err(NativeApprovalError::WrongPin {
                    remaining: remaining_attempts,
                });
            }
            PinVerify::Locked { remaining_secs } => {
                lease::discard_native_preview().await;
                return Err(NativeApprovalError::PinLocked { remaining_secs });
            }
            PinVerify::Disabled => {
                lease::discard_native_preview().await;
                return Err(NativeApprovalError::PinDisabled);
            }
        }
    }
    let activated = lease::approve_lease_native(
        &info.id,
        master_password.expose_secret().as_bytes(),
        &approved_hosts,
    )
    .await;
    if activated.is_err() {
        lease::discard_native_preview().await;
    }
    activated.map_err(Into::into)
}

fn helper_path() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let exe = std::env::current_exe().ok()?;
        let macos = exe.parent()?;
        let contents = macos.parent()?;
        Some(
            contents
                .join("Helpers")
                .join("Sloosh Approval.app")
                .join("Contents")
                .join("MacOS")
                .join("sloosh-approval"),
        )
    }
    #[cfg(not(target_os = "macos"))]
    None
}

fn validate_helper(path: &Path) -> Result<(), NativeApprovalError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            NativeApprovalError::Unavailable
        } else {
            NativeApprovalError::Io(error)
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(NativeApprovalError::Unavailable);
    }
    // SAFETY: geteuid has no arguments and only reads process credentials.
    let effective_uid = unsafe { libc::geteuid() };
    if !matches!(metadata.uid(), 0) && metadata.uid() != effective_uid {
        return Err(NativeApprovalError::Unavailable);
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(NativeApprovalError::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temporary_helper_path(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "sloosh-helper-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn helper_error_codes_preserve_fallback_meaning() {
        assert!(matches!(
            map_helper_error("not_enrolled".into(), "ignored".into()),
            NativeApprovalError::NotEnrolled
        ));
        assert!(matches!(
            map_helper_error("cancelled".into(), "ignored".into()),
            NativeApprovalError::Cancelled
        ));
    }

    #[test]
    fn helper_validation_rejects_group_writable_executable() {
        let path = temporary_helper_path("group-writable");
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .expect("create helper");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o775))
            .expect("set helper mode");

        assert!(matches!(
            validate_helper(&path),
            Err(NativeApprovalError::Unavailable)
        ));
        std::fs::remove_file(path).expect("remove temporary helper");
    }

    #[test]
    fn helper_validation_accepts_owner_only_executable() {
        let path = temporary_helper_path("owner-only");
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .expect("create helper");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("set helper mode");

        validate_helper(&path).expect("validate owner-only helper");
        std::fs::remove_file(path).expect("remove temporary helper");
    }
}
