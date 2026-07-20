//! CLI-owned local filesystem half of SFTP transfers.

use std::path::Path;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use zeroize::Zeroizing;

use super::args::{GetArgs, PutArgs};
use super::{bail_on_error_or_unexpected, client, lease_token_from_env};
use crate::proto::{Request, Response};
use crate::transport::unix::{self, UnixChannel};
use crate::transport::{Channel, MAX_RAW_FRAME_BYTES};

/// Resolve a user-facing path against this CLI process's cwd. The daemon
/// receives the result only as an audit/display label and never opens it.
pub(super) fn resolve_local_path(path: &str) -> anyhow::Result<String> {
    let path_ref = Path::new(path);
    if path_ref.is_absolute() {
        return Ok(path.to_string());
    }
    let cwd = std::env::current_dir().map_err(|error| {
        anyhow::anyhow!(
            "could not resolve local path '{path}' to an absolute path: could not determine \
             the current directory ({error})"
        )
    })?;
    Ok(cwd.join(path_ref).to_string_lossy().into_owned())
}

pub(super) async fn open_local_upload(path: &str) -> anyhow::Result<tokio::fs::File> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|error| anyhow::anyhow!("local upload '{path}' is not readable: {error}"))?;
    if !metadata.is_file() {
        anyhow::bail!("local upload '{path}' is not a regular file");
    }
    tokio::fs::File::open(path)
        .await
        .map_err(|error| anyhow::anyhow!("could not open local upload '{path}': {error}"))
}

pub(super) struct LocalDownload {
    destination: std::path::PathBuf,
    pub(super) temp: std::path::PathBuf,
    file: Option<tokio::fs::File>,
    force: bool,
    committed: bool,
}

impl LocalDownload {
    pub(super) async fn open(path: &Path, force: bool) -> anyhow::Result<Self> {
        if !force && tokio::fs::try_exists(path).await.unwrap_or(false) {
            anyhow::bail!(
                "local destination '{}' already exists; pass --force to replace it",
                path.display()
            );
        }
        let parent = path.parent().ok_or_else(|| {
            anyhow::anyhow!("local destination '{}' has no parent", path.display())
        })?;
        if !parent.is_dir() {
            anyhow::bail!(
                "local destination directory '{}' does not exist",
                parent.display()
            );
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("download");
        let temp = parent.join(format!(
            ".{name}.sloosh-{}-{:016x}.tmp",
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.mode(0o666);
        }
        let file = options.open(&temp).await.map_err(|error| {
            anyhow::anyhow!("could not create local download temp file: {error}")
        })?;
        Ok(Self {
            destination: path.to_path_buf(),
            temp,
            file: Some(file),
            force,
            committed: false,
        })
    }

    pub(super) async fn write_chunk(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.file
            .as_mut()
            .expect("download file remains open until finish")
            .write_all(data)
            .await
            .map_err(|error| anyhow::anyhow!("could not write local download: {error}"))
    }

    pub(super) async fn finish(mut self) -> anyhow::Result<()> {
        let file = self
            .file
            .take()
            .expect("download file remains open until finish");
        file.sync_all()
            .await
            .map_err(|error| anyhow::anyhow!("could not flush local download: {error}"))?;
        drop(file);

        let temp = self.temp.clone();
        let destination = self.destination.clone();
        let force = self.force;
        tokio::task::spawn_blocking(move || {
            if force {
                std::fs::rename(&temp, &destination).map_err(|error| {
                    anyhow::anyhow!(
                        "could not replace local destination '{}': {error}",
                        destination.display()
                    )
                })?;
            } else {
                std::fs::hard_link(&temp, &destination).map_err(|error| {
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        anyhow::anyhow!(
                            "local destination '{}' already exists; pass --force to replace it",
                            destination.display()
                        )
                    } else {
                        anyhow::anyhow!(
                            "could not create local destination '{}': {error}",
                            destination.display()
                        )
                    }
                })?;
                std::fs::remove_file(&temp).map_err(|error| {
                    anyhow::anyhow!("download succeeded but temp-file cleanup failed: {error}")
                })?;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
        .map_err(|error| anyhow::anyhow!("local download finalizer failed: {error}"))??;
        self.committed = true;
        Ok(())
    }
}

impl Drop for LocalDownload {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.temp);
        }
    }
}

async fn connect_for_transfer() -> anyhow::Result<UnixChannel> {
    client::connect_or_spawn(&unix::resolve_socket_path()).await
}

async fn expect_transfer_ready(channel: &mut UnixChannel, operation: &str) -> anyhow::Result<()> {
    let response = channel
        .recv::<Response>()
        .await?
        .ok_or_else(|| anyhow::anyhow!("daemon closed before {operation} became ready"))?;
    match bail_on_error_or_unexpected(response)? {
        Response::TransferReady => Ok(()),
        other => anyhow::bail!("daemon sent an unexpected reply to {operation}: {other:?}"),
    }
}

pub(super) async fn cmd_put(args: PutArgs) -> anyhow::Result<()> {
    let local_path = resolve_local_path(&args.local_path)?;
    let mut local_file = open_local_upload(&local_path).await?;
    let request = Request::Put {
        host: args.host,
        local_path: local_path.clone(),
        remote_path: args.remote_path,
        session: args.session,
        lease_token: lease_token_from_env(),
    };
    let mut channel = connect_for_transfer().await?;
    channel.send(&request).await?;
    expect_transfer_ready(&mut channel, "Put").await?;

    let mut buffer = Zeroizing::new(vec![0_u8; MAX_RAW_FRAME_BYTES]);
    loop {
        let read = local_file
            .read(buffer.as_mut_slice())
            .await
            .map_err(|error| {
                anyhow::anyhow!("could not read local upload '{local_path}': {error}")
            })?;
        if read == 0 {
            break;
        }
        channel.send_raw_frame(&buffer[..read]).await?;
    }
    channel.send_raw_frame(&[]).await?;

    let response = channel
        .recv::<Response>()
        .await?
        .ok_or_else(|| anyhow::anyhow!("daemon closed before Put completed"))?;
    let Response::Transfer(reply) = bail_on_error_or_unexpected(response)? else {
        anyhow::bail!("daemon sent an unexpected final reply to Put");
    };
    println!(
        "put: {} -> {}:{} ({} bytes)",
        reply.local_path, reply.host, reply.remote_path, reply.bytes_transferred
    );
    Ok(())
}

pub(super) async fn cmd_get(args: GetArgs) -> anyhow::Result<()> {
    let local_path = resolve_local_path(&args.local_path)?;
    let mut local_file = LocalDownload::open(Path::new(&local_path), args.force).await?;
    let request = Request::Get {
        host: args.host,
        remote_path: args.remote_path,
        local_path: local_path.clone(),
        session: args.session,
        lease_token: lease_token_from_env(),
    };
    let mut channel = connect_for_transfer().await?;
    channel.send(&request).await?;
    expect_transfer_ready(&mut channel, "Get").await?;
    while let Some(chunk) = channel.recv_raw_frame().await? {
        let chunk = Zeroizing::new(chunk);
        local_file.write_chunk(&chunk).await?;
    }
    let response = channel
        .recv::<Response>()
        .await?
        .ok_or_else(|| anyhow::anyhow!("daemon closed before Get completed"))?;
    let Response::Transfer(reply) = bail_on_error_or_unexpected(response)? else {
        anyhow::bail!("daemon sent an unexpected final reply to Get");
    };
    local_file.finish().await?;
    println!(
        "get: {}:{} -> {} ({} bytes)",
        reply.host, reply.remote_path, reply.local_path, reply.bytes_transferred
    );
    Ok(())
}
