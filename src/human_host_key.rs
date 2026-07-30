//! Human-owned SSH host-key bootstrap for desktop clients.
//!
//! The final target is probed only far enough to obtain its public host key.
//! ProxyJump dependencies use their normal strict host-key verification and
//! authentication. Callers must show the returned fingerprint to a human and
//! obtain explicit confirmation before calling [`apply_host_key_action`].

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::daemon::{ssh, vault};
use crate::proto::SecretString;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyTrustPreview {
    pub requested_host: String,
    pub host: String,
    pub hostname: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    pub state: HostKeyTrustState,
    pub source: Option<HostKeyTrustSource>,
    pub stored_fingerprint: Option<String>,
    pub replaceable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyTrustState {
    New,
    Changed,
    ExternalMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyTrustSource {
    Sloosh,
    OpenSsh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyTrustAction {
    Add,
    Replace,
}

#[derive(Debug, Error)]
pub enum HostKeyTrustError {
    #[error("another host-key operation is already using this process's vault cache")]
    VaultCacheInUse,
    #[error(transparent)]
    Vault(#[from] vault::VaultError),
    #[error(transparent)]
    Ssh(#[from] ssh::SshError),
    #[error(
        "the host-key preview changed before confirmation; inspect the new endpoint and fingerprint"
    )]
    PreviewChanged,
    #[error("all host keys in this route are already trusted")]
    AlreadyTrusted,
    #[error("this host key cannot be changed by the requested action")]
    InvalidAction,
}

async fn first_actionable_preview(
    requested_host: &str,
) -> Result<
    Option<(
        ssh::HostKeyConfirmationTarget,
        ssh::HostKeyProbeResult,
        ssh::HostKeyTrustState,
    )>,
    HostKeyTrustError,
> {
    let targets = ssh::host_key_confirmation_order(&[requested_host.to_string()]).await?;
    for target in targets {
        let probe = ssh::fetch_host_key_for_confirmation_target(&target).await?;
        let trust = ssh::inspect_host_key_trust(&probe.hostname, probe.port, &probe.key)?;
        if !matches!(trust, ssh::HostKeyTrustState::Trusted) {
            return Ok(Some((target, probe, trust)));
        }
    }
    Ok(None)
}

fn preview_from_probe(
    requested_host: &str,
    target: &ssh::HostKeyConfirmationTarget,
    probe: &ssh::HostKeyProbeResult,
    trust: ssh::HostKeyTrustState,
) -> HostKeyTrustPreview {
    let (state, source, stored_fingerprint, replaceable) = match trust {
        ssh::HostKeyTrustState::Trusted => unreachable!("trusted keys do not need a preview"),
        ssh::HostKeyTrustState::Unknown => (HostKeyTrustState::New, None, None, true),
        ssh::HostKeyTrustState::Changed {
            source: ssh::KnownHostSource::Sloosh,
            stored_fingerprint,
            replaceable,
        } => (
            HostKeyTrustState::Changed,
            Some(HostKeyTrustSource::Sloosh),
            Some(stored_fingerprint),
            replaceable,
        ),
        ssh::HostKeyTrustState::Changed {
            source: ssh::KnownHostSource::OpenSsh,
            stored_fingerprint,
            ..
        } => (
            HostKeyTrustState::ExternalMismatch,
            Some(HostKeyTrustSource::OpenSsh),
            Some(stored_fingerprint),
            false,
        ),
    };
    HostKeyTrustPreview {
        requested_host: requested_host.to_string(),
        host: target.alias.clone(),
        hostname: probe.hostname.clone(),
        port: probe.port,
        algorithm: probe.key.algorithm().to_string(),
        fingerprint: probe
            .key
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string(),
        state,
        source,
        stored_fingerprint,
        replaceable,
    }
}

async fn preview_unlocked(
    requested_host: &str,
) -> Result<Option<HostKeyTrustPreview>, HostKeyTrustError> {
    let Some((target, probe, trust)) = first_actionable_preview(requested_host).await? else {
        return Ok(None);
    };
    Ok(Some(preview_from_probe(
        requested_host,
        &target,
        &probe,
        trust,
    )))
}

pub async fn preview_host_key(
    requested_host: &str,
    master_password: &SecretString,
) -> Result<Option<HostKeyTrustPreview>, HostKeyTrustError> {
    match vault::with_temporary_cache(master_password.expose_secret().as_bytes(), || {
        preview_unlocked(requested_host)
    })
    .await
    {
        Ok(preview) => Ok(preview),
        Err(vault::TemporaryCacheError::CacheInUse) => Err(HostKeyTrustError::VaultCacheInUse),
        Err(vault::TemporaryCacheError::Vault(error)) => Err(error.into()),
        Err(vault::TemporaryCacheError::Operation(error)) => Err(error),
    }
}

pub async fn apply_host_key_action(
    expected: &HostKeyTrustPreview,
    action: HostKeyTrustAction,
    master_password: &SecretString,
) -> Result<(), HostKeyTrustError> {
    match vault::with_temporary_cache(master_password.expose_secret().as_bytes(), || async {
        let Some((target, probe, trust)) =
            first_actionable_preview(&expected.requested_host).await?
        else {
            return Err(HostKeyTrustError::AlreadyTrusted);
        };
        let observed = preview_from_probe(&expected.requested_host, &target, &probe, trust);
        if &observed != expected {
            return Err(HostKeyTrustError::PreviewChanged);
        }
        match (action, observed.state) {
            (HostKeyTrustAction::Add, HostKeyTrustState::New) => {
                ssh::record_sloosh_known_host(&probe.hostname, probe.port, &probe.key)?;
            }
            (HostKeyTrustAction::Replace, HostKeyTrustState::Changed) if observed.replaceable => {
                ssh::replace_sloosh_known_host(
                    &probe.hostname,
                    probe.port,
                    &probe.key,
                    observed
                        .stored_fingerprint
                        .as_deref()
                        .ok_or(HostKeyTrustError::InvalidAction)?,
                )?;
            }
            _ => return Err(HostKeyTrustError::InvalidAction),
        }
        Ok(())
    })
    .await
    {
        Ok(()) => Ok(()),
        Err(vault::TemporaryCacheError::CacheInUse) => Err(HostKeyTrustError::VaultCacheInUse),
        Err(vault::TemporaryCacheError::Vault(error)) => Err(error.into()),
        Err(vault::TemporaryCacheError::Operation(error)) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_preview_keeps_requested_and_resolved_host_separate() {
        let preview = HostKeyTrustPreview {
            requested_host: "production".into(),
            host: "bastion".into(),
            hostname: "bastion.example.com".into(),
            port: 2222,
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:example".into(),
            state: HostKeyTrustState::New,
            source: None,
            stored_fingerprint: None,
            replaceable: true,
        };
        assert_eq!(preview.requested_host, "production");
        assert_eq!(preview.host, "bastion");
    }

    #[test]
    fn preview_equality_rejects_every_human_visible_change() {
        let expected = HostKeyTrustPreview {
            requested_host: "production".into(),
            host: "bastion".into(),
            hostname: "bastion.example.com".into(),
            port: 2222,
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:expected".into(),
            state: HostKeyTrustState::New,
            source: None,
            stored_fingerprint: None,
            replaceable: true,
        };
        for changed in [
            HostKeyTrustPreview {
                host: "other".into(),
                ..expected.clone()
            },
            HostKeyTrustPreview {
                hostname: "other.example.com".into(),
                ..expected.clone()
            },
            HostKeyTrustPreview {
                port: 22,
                ..expected.clone()
            },
            HostKeyTrustPreview {
                fingerprint: "SHA256:changed".into(),
                ..expected.clone()
            },
            HostKeyTrustPreview {
                algorithm: "ssh-rsa".into(),
                ..expected.clone()
            },
            HostKeyTrustPreview {
                state: HostKeyTrustState::Changed,
                ..expected.clone()
            },
            HostKeyTrustPreview {
                source: Some(HostKeyTrustSource::Sloosh),
                ..expected.clone()
            },
            HostKeyTrustPreview {
                stored_fingerprint: Some("SHA256:old".into()),
                ..expected.clone()
            },
            HostKeyTrustPreview {
                replaceable: false,
                ..expected.clone()
            },
        ] {
            assert_ne!(changed, expected);
        }
    }
}
