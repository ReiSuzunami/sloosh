//! Tauri commands for vault-backed host inventory.

use serde::Deserialize;
use sloosh::proto::{
    HostAuth, HostAuthKind, HostRoute, HostSummary, Request, Response, SecretString,
};

use super::Controller;
use super::gui_error::{daemon_request_failed, unexpected_daemon_response};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HostInput {
    alias: String,
    hostname: String,
    port: Option<u16>,
    user: Option<String>,
    auth: HostAuthKind,
    password: Option<SecretString>,
    key_file: Option<String>,
    route: HostRoute,
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
) -> Result<Vec<HostSummary>, String> {
    let controller = controller.inner().clone();
    let password = controller.master_password()?;
    host_inventory(&controller, password).await
}

#[tauri::command]
pub(crate) async fn add_host(
    controller: tauri::State<'_, Controller>,
    mut host: HostInput,
) -> Result<(), String> {
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
        Response::Ok => Ok(()),
        Response::Error { message } => Err(message),
        _ => Err(unexpected_daemon_response("adding a host")),
    }
}

#[tauri::command(rename_all = "camelCase")]
pub(crate) async fn update_host(
    controller: tauri::State<'_, Controller>,
    mut host: HostInput,
    change_auth: bool,
) -> Result<(), String> {
    let controller = controller.inner().clone();
    let master_password = controller.master_password()?;
    let auth = if change_auth {
        Some(host_auth(&mut host)?)
    } else {
        None
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
        Response::Ok => Ok(()),
        Response::Error { message } => Err(message),
        _ => Err(unexpected_daemon_response("updating a host")),
    }
}

#[tauri::command]
pub(crate) async fn remove_host(
    controller: tauri::State<'_, Controller>,
    alias: String,
) -> Result<(), String> {
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

    fn host_input(auth: HostAuthKind) -> HostInput {
        HostInput {
            alias: "example".into(),
            hostname: "example.test".into(),
            port: None,
            user: None,
            auth,
            password: None,
            key_file: None,
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
