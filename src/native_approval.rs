//! Native human-approval adapter.
//!
//! Rust owns policy and lease activation. Bundled macOS helper owns
//! Keychain/Touch ID UI and returns a short-lived vault password only over
//! anonymous pipes inherited from the trusted daemon or desktop process.

use crate::daemon::{lease, ssh, vault};
use crate::local_approval::{PinError, PinStatus, PinStore, PinVerify};
use crate::proto::{LeaseActivatedInfo, LeaseRequestSummary, SecretString};
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
#[cfg(test)]
use std::path::PathBuf;

mod helper;

use helper::{HelperProcess, HelperRequest, HelperResponse, helper_path, validate_helper};

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
    #[error(transparent)]
    Ssh(#[from] ssh::SshError),
    #[error("wrong approval PIN ({remaining} attempt(s) remain)")]
    WrongPin { remaining: u32 },
    #[error("approval PIN is locked for {remaining_secs} seconds")]
    PinLocked { remaining_secs: u64 },
    #[error("approval PIN was disabled after too many failed attempts; re-enable it in Sloosh")]
    PinDisabled,
}

fn map_helper_error(code: String, message: String) -> NativeApprovalError {
    match code.as_str() {
        "not_enrolled" => NativeApprovalError::NotEnrolled,
        "cancelled" => NativeApprovalError::Cancelled,
        "timeout" => NativeApprovalError::TimedOut,
        _ => NativeApprovalError::Helper(message),
    }
}

/// Explicit async cleanup state for the vault cache populated by native
/// approval preview. Rust `Drop` cannot await, so the post-preview flow has a
/// single outer error exit that calls this exactly once; success disarms it
/// after the daemon has installed an active lease that owns cache lifetime.
struct NativePreviewCleanup {
    armed: bool,
}

impl NativePreviewCleanup {
    fn armed() -> Self {
        Self { armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn take(&mut self) -> bool {
        std::mem::replace(&mut self.armed, false)
    }

    async fn cleanup(&mut self) {
        if self.take() {
            lease::discard_native_preview().await;
        }
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

#[derive(Debug)]
pub enum NativeApprovalOutcome {
    Human(LeaseActivatedInfo),
    SystemAgent(LeaseActivatedInfo),
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

pub async fn unlock_with_touch_id() -> Result<SecretString, NativeApprovalError> {
    let mut helper = HelperProcess::spawn().await?;
    match helper.exchange(&HelperRequest::UnlockWithTouchId).await? {
        HelperResponse::Unlocked { master_password } => {
            helper.finish().await?;
            Ok(master_password)
        }
        HelperResponse::Error { code, message } => Err(map_helper_error(code, message)),
        _ => Err(NativeApprovalError::InvalidData(
            "unexpected Touch ID unlock response".into(),
        )),
    }
}

pub async fn unlock_with_pin() -> Result<SecretString, NativeApprovalError> {
    let mut helper = HelperProcess::spawn().await?;
    let pin = match helper.exchange(&HelperRequest::BeginPinUnlock).await? {
        HelperResponse::PinEntered { pin } => pin,
        HelperResponse::Error { code, message } => return Err(map_helper_error(code, message)),
        _ => {
            return Err(NativeApprovalError::InvalidData(
                "unexpected PIN input response".into(),
            ));
        }
    };
    if let Err(error) = verify_pin(&PinStore::current_user(), &pin) {
        let _ = helper
            .exchange(&HelperRequest::CompletePinUnlock { verified: false })
            .await;
        let _ = helper.finish().await;
        return Err(error);
    }
    let master_password = match helper
        .exchange(&HelperRequest::CompletePinUnlock { verified: true })
        .await?
    {
        HelperResponse::Unlocked { master_password } => master_password,
        HelperResponse::Error { code, message } => return Err(map_helper_error(code, message)),
        _ => {
            return Err(NativeApprovalError::InvalidData(
                "unexpected PIN unlock response".into(),
            ));
        }
    };
    helper.finish().await?;
    Ok(master_password)
}

pub async fn prompt_ssh_password(host_label: &str) -> Result<SecretString, NativeApprovalError> {
    let mut helper = HelperProcess::spawn().await?;
    let response = helper
        .exchange(&HelperRequest::PromptSshPassword { host_label })
        .await?;
    match response {
        HelperResponse::SshPasswordEntered { ssh_password } => {
            helper.finish().await?;
            Ok(ssh_password)
        }
        HelperResponse::Error { code, message } => Err(map_helper_error(code, message)),
        _ => Err(NativeApprovalError::InvalidData(
            "unexpected SSH password response".into(),
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
) -> Result<NativeApprovalOutcome, NativeApprovalError> {
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

    let mut cleanup = NativePreviewCleanup::armed();
    let result = finish_native_approval(helper, info, &master_password).await;
    match result {
        Ok(outcome) => {
            cleanup.disarm();
            Ok(outcome)
        }
        Err(error) => {
            cleanup.cleanup().await;
            Err(error)
        }
    }
}

async fn finish_native_approval(
    mut helper: HelperProcess,
    info: &LeaseRequestSummary,
    master_password: &SecretString,
) -> Result<NativeApprovalOutcome, NativeApprovalError> {
    let approved_hosts =
        lease::preview_native_approval(&info.id, master_password.expose_secret().as_bytes())
            .await?;
    for host in &approved_hosts {
        let (hostname, port) = ssh::resolve_endpoint(host).await?;
        if !ssh::host_has_known_key(&hostname, port) {
            return Err(NativeApprovalError::HostKeyConfirmationRequired);
        }
    }
    if ssh::scope_uses_system_agent(&approved_hosts).await? {
        match helper.exchange(&HelperRequest::CompleteSystemAgent).await? {
            HelperResponse::SystemAgentReady => helper.finish().await?,
            HelperResponse::Error { code, message } => {
                return Err(map_helper_error(code, message));
            }
            _ => {
                return Err(NativeApprovalError::InvalidData(
                    "unexpected system-agent completion response".into(),
                ));
            }
        }
        return match lease::approve_lease_system_agent(&info.id, Some(&approved_hosts)).await? {
            lease::SystemAgentApprovalOutcome::Activated(activated) => {
                Ok(NativeApprovalOutcome::SystemAgent(activated))
            }
            lease::SystemAgentApprovalOutcome::NotEligible => {
                Err(NativeApprovalError::InvalidData(
                    "system-agent scope changed before lease activation".into(),
                ))
            }
        };
    }
    let pin_store = PinStore::current_user();
    let allow_pin = matches!(pin_store.status()?, PinStatus::Ready);
    let (entered_pin, entered_master_password) = match helper
        .exchange(&HelperRequest::Confirm {
            hosts: &approved_hosts,
            allow_pin,
        })
        .await?
    {
        HelperResponse::Approved => (None, None),
        HelperResponse::PinEntered { pin } => (Some(pin), None),
        HelperResponse::MasterPasswordEntered { master_password } => (None, Some(master_password)),
        HelperResponse::Error { code, message } => return Err(map_helper_error(code, message)),
        _ => {
            return Err(NativeApprovalError::InvalidData(
                "unexpected confirmation response".into(),
            ));
        }
    };
    helper.finish().await?;
    if let Some(pin) = entered_pin {
        verify_pin(&pin_store, &pin)?;
    }
    let approval_password = entered_master_password.as_ref().unwrap_or(master_password);
    Ok(NativeApprovalOutcome::Human(
        lease::approve_lease_native(
            &info.id,
            approval_password.expose_secret().as_bytes(),
            &approved_hosts,
        )
        .await?,
    ))
}

fn verify_pin(store: &PinStore, pin: &SecretString) -> Result<(), NativeApprovalError> {
    match store.verify(pin)? {
        PinVerify::Approved => Ok(()),
        PinVerify::Rejected { remaining_attempts } => Err(NativeApprovalError::WrongPin {
            remaining: remaining_attempts,
        }),
        PinVerify::Locked { remaining_secs } => {
            Err(NativeApprovalError::PinLocked { remaining_secs })
        }
        PinVerify::Disabled => Err(NativeApprovalError::PinDisabled),
    }
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
        assert!(matches!(
            map_helper_error("timeout".into(), "ignored".into()),
            NativeApprovalError::TimedOut
        ));
    }

    #[test]
    fn native_preview_cleanup_is_exactly_once_and_disarmable() {
        let mut failure = NativePreviewCleanup::armed();
        assert!(failure.take());
        assert!(!failure.take());

        let mut success = NativePreviewCleanup::armed();
        success.disarm();
        assert!(!success.take());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn native_approval_is_unavailable_off_macos() {
        assert!(helper_path().is_none());
        assert!(!is_available());
    }

    #[test]
    fn desktop_unlock_requests_have_stable_helper_names() {
        assert_eq!(
            serde_json::to_value(HelperRequest::UnlockWithTouchId).unwrap(),
            serde_json::json!({ "type": "unlock_with_touch_id" })
        );
        assert_eq!(
            serde_json::to_value(HelperRequest::BeginPinUnlock).unwrap(),
            serde_json::json!({ "type": "begin_pin_unlock" })
        );
        assert_eq!(
            serde_json::to_value(HelperRequest::CompletePinUnlock { verified: true }).unwrap(),
            serde_json::json!({ "type": "complete_pin_unlock", "verified": true })
        );
        assert_eq!(
            serde_json::to_value(HelperRequest::CompleteSystemAgent).unwrap(),
            serde_json::json!({ "type": "complete_system_agent" })
        );
    }

    #[test]
    fn helper_system_agent_response_is_typed() {
        let response: HelperResponse = serde_json::from_value(serde_json::json!({
            "type": "system_agent_ready"
        }))
        .unwrap();
        assert!(matches!(response, HelperResponse::SystemAgentReady));
    }

    #[test]
    fn helper_master_password_response_remains_typed_and_secret() {
        let response: HelperResponse = serde_json::from_value(serde_json::json!({
            "type": "master_password_entered",
            "master_password": "vault-secret"
        }))
        .unwrap();
        let HelperResponse::MasterPasswordEntered { master_password } = response else {
            panic!("expected Master Password response");
        };
        assert_eq!(master_password.expose_secret(), "vault-secret");
        assert_eq!(format!("{master_password:?}"), "SecretString(<redacted>)");
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
