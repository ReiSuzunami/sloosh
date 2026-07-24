//! Bundled native-helper process validation and bounded NDJSON IPC.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use zeroize::Zeroizing;

use super::NativeApprovalError;
use crate::proto::SecretString;

const MAX_HELPER_MESSAGE_BYTES: usize = 64 * 1024;
const HELPER_INTERACTION_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const HELPER_EXIT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum HelperRequest<'a> {
    Status,
    UnlockWithTouchId,
    BeginPinUnlock,
    CompletePinUnlock {
        verified: bool,
    },
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
    PromptSshPassword {
        host_label: &'a str,
    },
    StorePinCredential {
        master_password: &'a str,
    },
    PromptPin,
    RemovePinCredential,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum HelperResponse {
    Enrolled,
    Unlocked {
        master_password: SecretString,
    },
    Approved,
    MasterPasswordEntered {
        master_password: SecretString,
    },
    SshPasswordEntered {
        ssh_password: SecretString,
    },
    PinEntered {
        pin: SecretString,
    },
    PinRejected,
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

pub(super) struct HelperProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl HelperProcess {
    pub(super) async fn spawn() -> Result<Self, NativeApprovalError> {
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

    pub(super) async fn exchange(
        &mut self,
        request: &HelperRequest<'_>,
    ) -> Result<HelperResponse, NativeApprovalError> {
        self.send_request(request).await?;
        self.receive_response().await
    }

    async fn send_request(
        &mut self,
        request: &HelperRequest<'_>,
    ) -> Result<(), NativeApprovalError> {
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
        Ok(())
    }

    async fn receive_response(&mut self) -> Result<HelperResponse, NativeApprovalError> {
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

    pub(super) async fn finish(mut self) -> Result<(), NativeApprovalError> {
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

pub(super) fn helper_path() -> Option<PathBuf> {
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

pub(super) fn validate_helper(path: &Path) -> Result<(), NativeApprovalError> {
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
