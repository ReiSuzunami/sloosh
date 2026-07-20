//! Remote-only SFTP transfer state.
//!
//! Local paths are opaque labels here. The CLI opens every local source and
//! destination and streams bounded frames; this module never touches the
//! caller's local filesystem.

use russh_sftp::client::error::Error as SftpClientError;
use russh_sftp::client::fs::File as SftpFile;
use russh_sftp::client::{Config as SftpConfig, SftpSession};
use russh_sftp::protocol::{OpenFlags, StatusCode};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{SessionError, default_session_name, get_or_create_session};
use crate::daemon::audit;
use crate::daemon::ssh::{self, SshError};
use crate::proto::TransferReply;

const SFTP_REQUEST_TIMEOUT_SECS: u64 = u64::MAX;

fn sftp_client_config() -> SftpConfig {
    SftpConfig {
        request_timeout_secs: SFTP_REQUEST_TIMEOUT_SECS,
        ..SftpConfig::default()
    }
}

async fn sftp_session(
    host: &str,
    session: Option<String>,
    lease_ctx: ssh::LeaseContext,
) -> Result<(String, SftpSession), SessionError> {
    let name = default_session_name(session);
    let inner = get_or_create_session(host, &name, &lease_ctx).await?;
    let channel = inner
        ._connection
        .handle
        .channel_open_session()
        .await
        .map_err(SshError::from)?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(SshError::from)?;
    let sftp = SftpSession::new_with_config(channel.into_stream(), sftp_client_config())
        .await
        .map_err(|error| SessionError::Sftp {
            host: host.to_string(),
            reason: error.to_string(),
        })?;
    Ok((name, sftp))
}

fn remote_path_error(host: &str, path: &str, error: SftpClientError) -> SessionError {
    if let SftpClientError::Status(status) = &error {
        let reason = match status.status_code {
            StatusCode::NoSuchFile => Some("no such file or directory"),
            StatusCode::PermissionDenied => Some("permission denied"),
            _ => None,
        };
        if let Some(reason) = reason {
            return SessionError::RemotePath {
                host: host.to_string(),
                path: path.to_string(),
                reason: reason.to_string(),
            };
        }
    }
    SessionError::Sftp {
        host: host.to_string(),
        reason: error.to_string(),
    }
}

/// Open the remote half of an upload. `local_path` remains an audit/display
/// label; the daemon never opens it.
pub async fn begin_put(
    host: &str,
    session: Option<String>,
    local_path: &str,
    remote_path: &str,
    lease_ctx: ssh::LeaseContext,
) -> Result<UploadTransfer, SessionError> {
    let (session_name, sftp) = sftp_session(host, session, lease_ctx).await?;
    let remote_file = sftp
        .open_with_flags(
            remote_path,
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
        )
        .await
        .map_err(|error| remote_path_error(host, remote_path, error))?;
    Ok(UploadTransfer {
        host: host.to_string(),
        session: session_name,
        local_path: local_path.to_string(),
        remote_path: remote_path.to_string(),
        remote_file,
        bytes_transferred: 0,
    })
}

pub struct UploadTransfer {
    host: String,
    session: String,
    local_path: String,
    remote_path: String,
    remote_file: SftpFile,
    bytes_transferred: u64,
}

impl UploadTransfer {
    pub async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), SessionError> {
        self.remote_file
            .write_all(chunk)
            .await
            .map_err(|source| SessionError::Transfer {
                host: self.host.clone(),
                local: self.local_path.clone(),
                remote: self.remote_path.clone(),
                source,
            })?;
        self.bytes_transferred = self.bytes_transferred.saturating_add(chunk.len() as u64);
        Ok(())
    }

    pub async fn finish(mut self) -> Result<TransferReply, SessionError> {
        self.remote_file
            .shutdown()
            .await
            .map_err(|source| SessionError::Transfer {
                host: self.host.clone(),
                local: self.local_path.clone(),
                remote: self.remote_path.clone(),
                source,
            })?;
        audit::record(
            "put",
            serde_json::json!({
                "host": self.host,
                "session": self.session,
                "local_path": self.local_path,
                "remote_path": self.remote_path,
                "bytes": self.bytes_transferred,
            }),
        );
        Ok(TransferReply {
            host: self.host,
            session: self.session,
            local_path: self.local_path,
            remote_path: self.remote_path,
            bytes_transferred: self.bytes_transferred,
        })
    }
}

/// Open the remote half of a download. `local_path` remains an audit/display
/// label; the CLI owns destination creation and atomic commit.
pub async fn begin_get(
    host: &str,
    session: Option<String>,
    remote_path: &str,
    local_path: &str,
    lease_ctx: ssh::LeaseContext,
) -> Result<DownloadTransfer, SessionError> {
    let (session_name, sftp) = sftp_session(host, session, lease_ctx).await?;
    let remote_file = sftp
        .open(remote_path)
        .await
        .map_err(|error| remote_path_error(host, remote_path, error))?;
    Ok(DownloadTransfer {
        host: host.to_string(),
        session: session_name,
        local_path: local_path.to_string(),
        remote_path: remote_path.to_string(),
        remote_file,
        bytes_transferred: 0,
    })
}

pub struct DownloadTransfer {
    host: String,
    session: String,
    local_path: String,
    remote_path: String,
    remote_file: SftpFile,
    bytes_transferred: u64,
}

impl DownloadTransfer {
    pub async fn read_chunk(&mut self, buffer: &mut [u8]) -> Result<usize, SessionError> {
        let read =
            self.remote_file
                .read(buffer)
                .await
                .map_err(|source| SessionError::Transfer {
                    host: self.host.clone(),
                    local: self.local_path.clone(),
                    remote: self.remote_path.clone(),
                    source,
                })?;
        self.bytes_transferred = self.bytes_transferred.saturating_add(read as u64);
        Ok(read)
    }

    pub fn finish(self) -> TransferReply {
        audit::record(
            "get",
            serde_json::json!({
                "host": self.host,
                "session": self.session,
                "local_path": self.local_path,
                "remote_path": self.remote_path,
                "bytes": self.bytes_transferred,
            }),
        );
        TransferReply {
            host: self.host,
            session: self.session,
            local_path: self.local_path,
            remote_path: self.remote_path,
            bytes_transferred: self.bytes_transferred,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_timeout_uses_tokios_far_future_path() {
        let config = sftp_client_config();
        assert_eq!(config.request_timeout_secs, u64::MAX);
        assert!(
            tokio::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(config.request_timeout_secs))
                .is_none(),
            "Tokio must route the maximum duration to its far-future path"
        );
    }
}
