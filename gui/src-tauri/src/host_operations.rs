//! Human-owned host-key bootstrap and end-to-end SSH connection checks.

use serde::{Deserialize, Serialize};
use sloosh::human_host_key::{
    self, HostKeyTrustAction, HostKeyTrustError, HostKeyTrustPreview, HostKeyTrustSource,
    HostKeyTrustState,
};
use sloosh::proto::{Request, Response};
use std::sync::atomic::{AtomicU64, Ordering};

use super::Controller;
use super::gui_error::{daemon_request_failed, unexpected_daemon_response};

static CONNECTION_TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HostKeyPreview {
    requested_host: String,
    host: String,
    hostname: String,
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
    let master_password = controller.master_password()?;
    human_host_key::preview_host_key(alias, &master_password)
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
    let master_password = controller.master_password()?;
    match human_host_key::apply_host_key_action(&preview.into(), action, &master_password).await {
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

fn connection_test_session() -> String {
    format!(
        "__sloosh_gui_connection_test_{}_{}",
        std::process::id(),
        CONNECTION_TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

async fn kill_test_session(controller: &Controller, host: &str, session: &str) {
    let _ = controller
        .client()
        .request(&Request::Kill {
            host: host.to_string(),
            session: Some(session.to_string()),
            lease_token: None,
        })
        .await;
}

fn connection_test_result(alias: &str, response: Response) -> Result<String, String> {
    match response {
        Response::Run(reply) if reply.state == "done" && reply.exit_code == Some(0) => Ok(format!(
            "Connected to {alias}; SSH handshake, host key, authentication, and remote shell all passed."
        )),
        Response::Run(reply) if reply.state == "running" => Err(format!(
            "Connected to {alias}, but the remote shell did not finish the test command within 15 seconds."
        )),
        Response::Run(reply) if reply.state == "dead" => Err(reply
            .dead_reason
            .unwrap_or_else(|| format!("The SSH session for {alias} closed during the test."))),
        Response::Run(reply) => Err(format!(
            "The SSH connection to {alias} opened, but the remote test command exited with {}.",
            reply
                .exit_code
                .map_or_else(|| "an unknown status".to_string(), |code| code.to_string())
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
                "Approval {} is still pending. Trust every unknown host key in this route, then retry the connection test.",
                info.id
            ));
        }
        Response::Error { message } => return Err(message),
        _ => {
            return Err(unexpected_daemon_response(
                "requesting connection-test approval",
            ));
        }
    }

    let session = connection_test_session();
    let response = client
        .request(&Request::Run {
            host: alias.clone(),
            command: "true".to_string(),
            session: Some(session.clone()),
            timeout_secs: 15,
            raw: false,
            lease_token: None,
        })
        .await
        .map_err(|_| daemon_request_failed("testing the SSH connection"));
    kill_test_session(&controller, &alias, &session).await;

    connection_test_result(&alias, response?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sloosh::proto::RunReply;

    #[test]
    fn host_key_preview_round_trips_through_the_desktop_shape() {
        let core = HostKeyTrustPreview {
            requested_host: "target".into(),
            host: "jump".into(),
            hostname: "jump.example.com".into(),
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

    fn run_reply(state: &str, exit_code: Option<i32>) -> Response {
        Response::Run(RunReply {
            host: "jump".into(),
            session: "test".into(),
            state: state.into(),
            exit_code,
            ..RunReply::default()
        })
    }

    #[test]
    fn connection_test_requires_a_completed_zero_exit() {
        assert!(connection_test_result("jump", run_reply("done", Some(0))).is_ok());
        assert!(
            connection_test_result("jump", run_reply("done", Some(7)))
                .unwrap_err()
                .contains("exited with 7")
        );
        assert!(
            connection_test_result("jump", run_reply("running", None))
                .unwrap_err()
                .contains("within 15 seconds")
        );
        assert!(
            connection_test_result("jump", run_reply("dead", None))
                .unwrap_err()
                .contains("closed during the test")
        );
        assert!(
            connection_test_result("jump", Response::Ok)
                .unwrap_err()
                .contains("unexpected response")
        );
    }
}
