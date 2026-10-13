//! Human-owned host-key bootstrap and end-to-end SSH connection checks.

use serde::{Deserialize, Serialize};
use sloosh::human_host_key::{
    self, HostKeyTrustAction, HostKeyTrustError, HostKeyTrustPreview, HostKeyTrustSource,
    HostKeyTrustState,
};
use sloosh::proto::{Request, Response};

use super::Controller;
use super::gui_error::{daemon_request_failed, unexpected_daemon_response};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HostKeyPreview {
    requested_host: String,
    host: String,
    hostname: String,
    host_key_alias: Option<String>,
    port: u16,
    algorithm: String,
    fingerprint: String,
    state: HostKeyTrustState,
    source: Option<HostKeyTrustSource>,
    stored_fingerprint: Option<String>,
    replaceable: bool,
}

impl From<HostKeyTrustPreview> for HostKeyPreview {
    fn from(preview: HostKeyTrustPreview) -> Self {
        Self {
            requested_host: preview.requested_host,
            host: preview.host,
            hostname: preview.hostname,
            host_key_alias: preview.host_key_alias,
            port: preview.port,
            algorithm: preview.algorithm,
            fingerprint: preview.fingerprint,
            state: preview.state,
            source: preview.source,
            stored_fingerprint: preview.stored_fingerprint,
            replaceable: preview.replaceable,
        }
    }
}

impl From<HostKeyPreview> for HostKeyTrustPreview {
    fn from(preview: HostKeyPreview) -> Self {
        Self {
            requested_host: preview.requested_host,
            host: preview.host,
            hostname: preview.hostname,
            host_key_alias: preview.host_key_alias,
            port: preview.port,
            algorithm: preview.algorithm,
            fingerprint: preview.fingerprint,
            state: preview.state,
            source: preview.source,
            stored_fingerprint: preview.stored_fingerprint,
            replaceable: preview.replaceable,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HostKeyActionResult {
    preview: Option<HostKeyPreview>,
    refreshed: bool,
}

async fn next_host_key_preview(
    controller: &Controller,
    alias: &str,
) -> Result<Option<HostKeyPreview>, String> {
    let master_password = if controller.unlock_snapshot().state == "unlocked" {
        Some(controller.master_password()?)
    } else {
        None
    };
    human_host_key::preview_host_key(alias, master_password.as_ref())
        .await
        .map(|preview| preview.map(Into::into))
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub(crate) async fn preview_host_key(
    controller: tauri::State<'_, Controller>,
    alias: String,
) -> Result<Option<HostKeyPreview>, String> {
    next_host_key_preview(controller.inner(), &alias).await
}

#[tauri::command]
pub(crate) async fn trust_host_key(
    controller: tauri::State<'_, Controller>,
    preview: HostKeyPreview,
    action: HostKeyTrustAction,
) -> Result<HostKeyActionResult, String> {
    let controller = controller.inner().clone();
    let requested_host = preview.requested_host.clone();
    let master_password = if controller.unlock_snapshot().state == "unlocked" {
        Some(controller.master_password()?)
    } else {
        None
    };
    match human_host_key::apply_host_key_action(&preview.into(), action, master_password.as_ref())
        .await
    {
        Ok(()) => Ok(HostKeyActionResult {
            preview: next_host_key_preview(&controller, &requested_host).await?,
            refreshed: false,
        }),
        Err(HostKeyTrustError::PreviewChanged | HostKeyTrustError::AlreadyTrusted) => {
            Ok(HostKeyActionResult {
                preview: next_host_key_preview(&controller, &requested_host).await?,
                refreshed: true,
            })
        }
        Err(error) => Err(error.to_string()),
    }
}

fn connection_test_result(alias: &str, response: Response) -> Result<String, String> {
    match response {
        Response::Ok => Ok(format!(
            "Connected to {alias}; host key, authentication, and SSH session channel passed. No remote command was executed."
        )),
        Response::Error { message } => Err(message),
        _ => Err(unexpected_daemon_response("testing the SSH connection")),
    }
}

#[tauri::command]
pub(crate) async fn test_host_connection(
    controller: tauri::State<'_, Controller>,
    alias: String,
) -> Result<String, String> {
    let controller = controller.inner().clone();
    let client = controller.client();
    match client
        .request(&Request::RequestLease {
            hosts: vec![alias.clone()],
        })
        .await
        .map_err(|_| daemon_request_failed("requesting connection-test approval"))?
    {
        Response::Ok => {}
        Response::LeaseRequestPending(info) => {
            return Err(format!(
                "Connection-test approval {} is still pending. Complete the native approval prompt or ask the user to run sloosh approve {} in another terminal, then test again.",
                info.id, info.id
            ));
        }
        Response::Error { message } => return Err(message),
        _ => {
            return Err(unexpected_daemon_response(
                "requesting connection-test approval",
            ));
        }
    }

    let response = client
        .request(&Request::TestConnection {
            host: alias.clone(),
            lease_token: None,
        })
        .await
        .map_err(|_| daemon_request_failed("testing the SSH connection"));

    connection_test_result(&alias, response?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_key_preview_round_trips_through_the_desktop_shape() {
        let core = HostKeyTrustPreview {
            requested_host: "target".into(),
            host: "jump".into(),
            hostname: "jump.example.com".into(),
            host_key_alias: Some("jump-key".into()),
            port: 2222,
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:example".into(),
            state: HostKeyTrustState::Changed,
            source: Some(HostKeyTrustSource::Sloosh),
            stored_fingerprint: Some("SHA256:old".into()),
            replaceable: true,
        };
        let desktop = HostKeyPreview::from(core.clone());
        assert_eq!(HostKeyTrustPreview::from(desktop), core);
    }

    #[test]
    fn connection_test_reports_protocol_success_and_visible_failures() {
        assert!(connection_test_result("jump", Response::Ok).is_ok());
        assert_eq!(
            connection_test_result(
                "jump",
                Response::Error {
                    message: "fixture failure".into()
                }
            )
            .unwrap_err(),
            "fixture failure"
        );
        assert!(connection_test_result("jump", Response::VaultExists { exists: false }).is_err());
    }
}
