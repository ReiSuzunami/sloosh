//! Human-owned SSH host-key bootstrap for desktop clients.
//!
//! The final target is probed only far enough to obtain its public host key.
//! ProxyJump dependencies use their normal strict host-key verification and
//! authentication. Callers must show the returned fingerprint to a human and
//! obtain explicit confirmation before calling [`trust_host_key`].

use thiserror::Error;

use crate::daemon::{ssh, vault};
use crate::proto::SecretString;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyTrustPreview {
    pub requested_host: String,
    pub host: String,
    pub hostname: String,
    pub port: u16,
    pub fingerprint: String,
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
    #[error("all host keys in this route are already recorded")]
    AlreadyTrusted,
}

async fn first_untrusted_target(
    requested_host: &str,
) -> Result<Option<ssh::HostKeyConfirmationTarget>, ssh::SshError> {
    let targets = ssh::host_key_confirmation_order(&[requested_host.to_string()]).await?;
    Ok(targets
        .into_iter()
        .find(|target| !ssh::host_has_known_key(&target.hostname, target.port)))
}

fn preview_from_probe(
    requested_host: &str,
    target: &ssh::HostKeyConfirmationTarget,
    probe: &ssh::HostKeyProbeResult,
) -> HostKeyTrustPreview {
    HostKeyTrustPreview {
        requested_host: requested_host.to_string(),
        host: target.alias.clone(),
        hostname: probe.hostname.clone(),
        port: probe.port,
        fingerprint: probe
            .key
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string(),
    }
}

async fn preview_unlocked(
    requested_host: &str,
) -> Result<Option<HostKeyTrustPreview>, HostKeyTrustError> {
    let Some(target) = first_untrusted_target(requested_host).await? else {
        return Ok(None);
    };
    let probe = ssh::fetch_host_key_for_confirmation_target(&target).await?;
    Ok(Some(preview_from_probe(requested_host, &target, &probe)))
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

pub async fn trust_host_key(
    expected: &HostKeyTrustPreview,
    master_password: &SecretString,
) -> Result<(), HostKeyTrustError> {
    match vault::with_temporary_cache(master_password.expose_secret().as_bytes(), || async {
        let Some(target) = first_untrusted_target(&expected.requested_host).await? else {
            return Err(HostKeyTrustError::AlreadyTrusted);
        };
        let probe = ssh::fetch_host_key_for_confirmation_target(&target).await?;
        let observed = preview_from_probe(&expected.requested_host, &target, &probe);
        if &observed != expected {
            return Err(HostKeyTrustError::PreviewChanged);
        }
        ssh::record_sloosh_known_host(&probe.hostname, probe.port, &probe.key)?;
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
            fingerprint: "SHA256:example".into(),
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
            fingerprint: "SHA256:expected".into(),
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
        ] {
            assert_ne!(changed, expected);
        }
    }
}
