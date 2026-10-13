//! Tauri commands for vault-backed host inventory.

use serde::{Deserialize, Serialize};
use sloosh::proto::{
    HostAuth, HostAuthKind, HostRoute, HostSummary, Request, Response, SecretString,
};

use super::Controller;
use super::gui_error::{daemon_request_failed, unexpected_daemon_response};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HostInput {
    source: String,
    alias: String,
    hostname: String,
    port: Option<u16>,
    user: Option<String>,
    auth: HostAuthKind,
    password: Option<SecretString>,
    key_file: Option<String>,
    private_key: Option<SecretString>,
    #[serde(default)]
    sync_to_agent: bool,
    route: HostRoute,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ManagedHost {
    #[serde(flatten)]
    host: HostSummary,
    source: &'static str,
    edit_error: Option<String>,
}

impl HostInput {
    fn summary(&self) -> HostSummary {
        HostSummary {
            alias: self.alias.clone(),
            hostname: self.hostname.clone(),
            port: self.port,
            user: self.user.clone(),
            auth: HostAuthKind::Agent,
            route: self.route.clone(),
        }
    }
}

async fn save_system_host(host: &mut HostInput, replace: bool) -> Result<Option<String>, String> {
    if host.auth == HostAuthKind::Password {
        return Err("Password profiles belong in the vault, under a separate alias.".into());
    }
    let sync = if host.sync_to_agent {
        Some(host_auth(host)?)
    } else {
        None
    };
    if host.auth != HostAuthKind::Agent && sync.is_none() {
        return Err("System-host keys must be loaded into SSH Agent on save.".into());
    }
    sloosh::system_hosts::save(&host.summary(), replace).map_err(|error| error.to_string())?;
    Ok(sync_saved_key(sync).await)
}

fn host_auth(input: &mut HostInput) -> Result<HostAuth, String> {
    match input.auth {
        HostAuthKind::Agent => Ok(HostAuth::Agent),
        HostAuthKind::Password => Ok(HostAuth::Password {
            password: input
                .password
                .take()
                .filter(|password| !password.expose_secret().is_empty())
                .ok_or_else(|| "Enter the SSH password.".to_string())?,
        }),
        HostAuthKind::KeyFile => Ok(HostAuth::KeyFile {
            path: input
                .key_file
                .clone()
                .filter(|path| !path.trim().is_empty())
                .ok_or_else(|| "Choose a private key file path.".to_string())?,
        }),
        HostAuthKind::PrivateKey => {
            let private_key = input
                .private_key
                .take()
                .ok_or_else(|| "Paste a private key.".to_string())?;
            sloosh::daemon::ssh::decode_vault_private_key(private_key.expose_secret())
                .map_err(|_| "Invalid or unsupported private key (maximum 256 KiB).".to_string())?;
            Ok(HostAuth::PrivateKey { private_key })
        }
    }
}

/// Only run after the vault save succeeds. Report partial success separately;
/// do not encourage retrying an already committed add operation.
async fn sync_saved_key(auth: Option<HostAuth>) -> Option<String> {
    let auth = auth?;
    let result = tauri::async_runtime::spawn_blocking(move || -> std::io::Result<bool> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut command = Command::new("/usr/bin/ssh-add");
        command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env("SSH_ASKPASS_REQUIRE", "force");
        match auth {
            HostAuth::KeyFile { path } => {
                let path = if let Some(relative) = path.strip_prefix("~/") {
                    std::path::PathBuf::from(
                        std::env::var_os("HOME")
                            .ok_or_else(|| std::io::Error::other("HOME is not set"))?,
                    )
                    .join(relative)
                } else {
                    std::path::PathBuf::from(path)
                };
                // An absolute path cannot be interpreted as an ssh-add option.
                let path = std::path::absolute(path)?;
                Ok(command.arg(path).stdin(Stdio::null()).status()?.success())
            }
            HostAuth::PrivateKey { private_key } => {
                let mut child = command.arg("-").stdin(Stdio::piped()).spawn()?;
                let written = child
                    .stdin
                    .take()
                    .expect("piped stdin")
                    .write_all(private_key.expose_secret().as_bytes());
                let status = child.wait()?;
                written?;
                Ok(status.success())
            }
            _ => Ok(false),
        }
    })
    .await;
    match result {
        Ok(Ok(true)) => None,
        _ => Some("Host saved, but ssh-add failed. Check the app's SSH_AUTH_SOCK and, for encrypted keys, configure SSH_ASKPASS or load the key manually. The daemon must use the same agent socket.".into()),
    }
}

fn key_to_sync(auth: &HostAuth, enabled: bool) -> Result<Option<HostAuth>, String> {
    if !enabled {
        return Ok(None);
    }
    match auth {
        HostAuth::KeyFile { .. } | HostAuth::PrivateKey { .. } => Ok(Some(auth.clone())),
        _ => Err("Only private-key authentication can be loaded into SSH Agent.".into()),
    }
}

async fn host_inventory(
    controller: &Controller,
    master_password: SecretString,
) -> Result<Vec<HostSummary>, String> {
    match controller
        .client()
        .request(&Request::ListHosts { master_password })
        .await
        .map_err(|_| daemon_request_failed("loading hosts"))?
    {
        Response::Hosts { hosts } => Ok(hosts),
        Response::Error { message } => Err(message),
        _ => Err(unexpected_daemon_response("loading hosts")),
    }
}

#[tauri::command]
pub(crate) async fn list_hosts(
    controller: tauri::State<'_, Controller>,
) -> Result<Vec<ManagedHost>, String> {
    let mut hosts = sloosh::system_hosts::list()
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|entry| ManagedHost {
            host: entry.host,
            source: "ssh_config",
            edit_error: entry.edit_error,
        })
        .collect::<Vec<_>>();
    if controller.unlock_snapshot().state == "unlocked" {
        let password = controller.master_password()?;
        for host in host_inventory(controller.inner(), password).await? {
            // Explicit SSH config aliases own the route, never the old vault copy.
            if !hosts.iter().any(|system| system.host.alias == host.alias) {
                hosts.push(ManagedHost {
                    host,
                    source: "vault",
                    edit_error: None,
                });
            }
        }
    }
    hosts.sort_by(|left, right| left.host.alias.cmp(&right.host.alias));
    Ok(hosts)
}

#[tauri::command]
pub(crate) async fn add_host(
    controller: tauri::State<'_, Controller>,
    mut host: HostInput,
) -> Result<Option<String>, String> {
    if host.source == "ssh_config" {
        return save_system_host(&mut host, false).await;
    }
    if sloosh::daemon::ssh::SshConfig::load_default().contains_alias(&host.alias) {
        return Err(
            "This alias is owned by SSH config. Edit the system host or use another alias.".into(),
        );
    }
    let controller = controller.inner().clone();
    let master_password = controller.master_password()?;
    let existing_hosts = host_inventory(&controller, master_password.clone()).await?;
    if existing_hosts.iter().any(|entry| entry.alias == host.alias) {
        return Err(format!(
            "'{}' is already in the vault - edit it or choose a different alias",
            host.alias
        ));
    }
    let auth = host_auth(&mut host)?;
    let sync = key_to_sync(&auth, host.sync_to_agent)?;
    match controller
        .client()
        .request(&Request::AddCred {
            alias: host.alias,
            hostname: host.hostname,
            port: host.port,
            user: host.user,
            auth,
            master_password,
            replace: false,
            route: host.route,
        })
        .await
        .map_err(|_| daemon_request_failed("adding a host"))?
    {
        Response::Ok => Ok(sync_saved_key(sync).await),
        Response::Error { message } => Err(message),
        _ => Err(unexpected_daemon_response("adding a host")),
    }
}

#[tauri::command(rename_all = "camelCase")]
pub(crate) async fn update_host(
    controller: tauri::State<'_, Controller>,
    mut host: HostInput,
    change_auth: bool,
) -> Result<Option<String>, String> {
    if host.source == "ssh_config" {
        let exists = sloosh::daemon::ssh::SshConfig::load_default().contains_alias(&host.alias);
        if !exists {
            return Err(
                "This system host no longer exists. Reload the list before editing.".into(),
            );
        }
        return save_system_host(&mut host, true).await;
    }
    if sloosh::daemon::ssh::SshConfig::load_default().contains_alias(&host.alias) {
        return Err(
            "This alias is owned by SSH config; use a different alias for a vault profile.".into(),
        );
    }
    let controller = controller.inner().clone();
    let master_password = controller.master_password()?;
    let auth = if change_auth {
        Some(host_auth(&mut host)?)
    } else {
        None
    };
    let sync = match &auth {
        Some(auth) => key_to_sync(auth, host.sync_to_agent)?,
        None if host.sync_to_agent => {
            return Err(
                "Select Change authentication and supply the key to load it into SSH Agent.".into(),
            );
        }
        None => None,
    };
    match controller
        .client()
        .request(&Request::UpdateHost {
            alias: host.alias,
            hostname: host.hostname,
            port: host.port,
            user: host.user,
            route: host.route,
            auth,
            master_password,
        })
        .await
        .map_err(|_| daemon_request_failed("updating a host"))?
    {
        Response::Ok => Ok(sync_saved_key(sync).await),
        Response::Error { message } => Err(message),
        _ => Err(unexpected_daemon_response("updating a host")),
    }
}

#[tauri::command]
pub(crate) async fn remove_host(
    controller: tauri::State<'_, Controller>,
    alias: String,
    source: String,
) -> Result<(), String> {
    if source == "ssh_config" {
        return sloosh::system_hosts::remove(&alias).map_err(|error| error.to_string());
    }
    let controller = controller.inner().clone();
    let master_password = controller.master_password()?;
    match controller
        .client()
        .request(&Request::RmCred {
            alias,
            master_password,
        })
        .await
        .map_err(|_| daemon_request_failed("removing a host"))?
    {
        Response::Ok => Ok(()),
        Response::Error { message } => Err(message),
        _ => Err(unexpected_daemon_response("removing a host")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_loading_requires_explicit_key_opt_in() {
        let key = HostAuth::KeyFile {
            path: "/fixture/key".into(),
        };
        assert!(key_to_sync(&key, false).unwrap().is_none());
        assert_eq!(key_to_sync(&key, true).unwrap(), Some(key));
        assert!(key_to_sync(&HostAuth::Agent, true).is_err());
        assert!(
            key_to_sync(
                &HostAuth::Password {
                    password: SecretString::new("fixture")
                },
                true
            )
            .is_err()
        );
        let inline = HostAuth::PrivateKey {
            private_key: SecretString::new("fixture-key"),
        };
        assert_eq!(key_to_sync(&inline, true).unwrap(), Some(inline));
        let mut input = host_input(HostAuthKind::PrivateKey);
        input.private_key = Some(SecretString::new("invalid-key-fixture"));
        let error = host_auth(&mut input).unwrap_err();
        assert!(!error.contains("invalid-key-fixture"));
        assert!(input.private_key.is_none());
    }

    fn host_input(auth: HostAuthKind) -> HostInput {
        HostInput {
            source: "vault".into(),
            alias: "example".into(),
            hostname: "example.test".into(),
            port: None,
            user: None,
            auth,
            password: None,
            key_file: None,
            private_key: None,
            sync_to_agent: false,
            route: HostRoute::Direct,
        }
    }

    #[test]
    fn password_auth_requires_and_consumes_form_secret() {
        let mut missing = host_input(HostAuthKind::Password);
        assert_eq!(
            host_auth(&mut missing).unwrap_err(),
            "Enter the SSH password."
        );

        let mut supplied = host_input(HostAuthKind::Password);
        supplied.password = Some(SecretString::new("ssh secret"));
        let HostAuth::Password { password } = host_auth(&mut supplied).unwrap() else {
            panic!("expected password auth");
        };
        assert_eq!(password.expose_secret(), "ssh secret");
        assert!(supplied.password.is_none());
    }

    #[test]
    fn agent_auth_needs_no_form_secret() {
        let mut input = host_input(HostAuthKind::Agent);
        assert_eq!(host_auth(&mut input).unwrap(), HostAuth::Agent);
    }

    #[test]
    fn key_file_auth_requires_a_selected_path() {
        let mut missing = host_input(HostAuthKind::KeyFile);
        assert_eq!(
            host_auth(&mut missing).unwrap_err(),
            "Choose a private key file path."
        );

        let mut supplied = host_input(HostAuthKind::KeyFile);
        supplied.key_file = Some("/Users/test/.ssh/id_ed25519".into());
        assert_eq!(
            host_auth(&mut supplied).unwrap(),
            HostAuth::KeyFile {
                path: "/Users/test/.ssh/id_ed25519".into()
            }
        );
    }
}
