#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod desktop_unlock;
mod dock_icon;
mod host_commands;
mod system_lock;

use desktop_unlock::{DEFAULT_ABSOLUTE_TIMEOUT, DesktopUnlockSession, UnlockMethod, UnlockStatus};
use serde::Serialize;
use sloosh::client::DaemonClient;
use sloosh::daemon::vault;
use sloosh::local_approval::{PinStatus, PinStore};
use sloosh::native_approval;
use sloosh::proto::{Request, Response, SecretString};
use sloosh::transport::unix;
use sloosh::vault_settings::{VaultSettingsStore, VaultTimeout};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use host_commands::{add_host, list_hosts, remove_host, update_host};

#[derive(Clone)]
struct Controller {
    daemon_executable: PathBuf,
    desktop_unlock: Arc<Mutex<DesktopUnlockSession>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DaemonSnapshot {
    online: bool,
    pid: Option<u32>,
    version: Option<String>,
    wire_protocol: Option<u32>,
    uptime_secs: Option<u64>,
    sessions: usize,
    leases: usize,
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppSnapshot {
    daemon: DaemonSnapshot,
    vault_exists: bool,
    skill_ready: bool,
    native_approval_available: bool,
    touch_id_enrolled: bool,
    pin: PinSnapshot,
    vault_unlock: VaultUnlockSnapshot,
    vault_timeout_minutes: u16,
    cli_path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultUnlockSnapshot {
    state: &'static str,
    method: Option<&'static str>,
    idle_remaining_secs: Option<u64>,
    absolute_remaining_secs: Option<u64>,
    idle_timeout_minutes: u16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PinSnapshot {
    state: &'static str,
    remaining_secs: Option<u64>,
    error: Option<String>,
}

impl From<Result<PinStatus, sloosh::local_approval::PinError>> for PinSnapshot {
    fn from(status: Result<PinStatus, sloosh::local_approval::PinError>) -> Self {
        match status {
            Ok(PinStatus::NotConfigured) => Self {
                state: "not_configured",
                remaining_secs: None,
                error: None,
            },
            Ok(PinStatus::Ready) => Self {
                state: "ready",
                remaining_secs: None,
                error: None,
            },
            Ok(PinStatus::Locked { remaining_secs }) => Self {
                state: "locked",
                remaining_secs: Some(remaining_secs),
                error: None,
            },
            Ok(PinStatus::Disabled) => Self {
                state: "disabled",
                remaining_secs: None,
                error: None,
            },
            Err(error) => Self {
                state: "error",
                remaining_secs: None,
                error: Some(error.to_string()),
            },
        }
    }
}

impl Controller {
    fn client(&self) -> DaemonClient {
        DaemonClient::new(unix::resolve_socket_path(), self.daemon_executable.clone())
    }

    async fn snapshot(&self) -> AppSnapshot {
        let client = self.client();
        let status = client.status().await;
        let vault_exists = if status.is_ok() {
            matches!(
                client.request(&Request::VaultExists).await,
                Ok(Response::VaultExists { exists: true })
            )
        } else {
            false
        };
        let daemon = match status {
            Ok(status) => DaemonSnapshot {
                online: true,
                pid: Some(status.pid),
                version: Some(status.version),
                wire_protocol: Some(status.wire_protocol),
                uptime_secs: Some(status.uptime_secs),
                sessions: status.sessions.len(),
                leases: status.leases.len(),
                error: None,
            },
            Err(error) => DaemonSnapshot {
                online: false,
                pid: None,
                version: None,
                wire_protocol: None,
                uptime_secs: None,
                sessions: 0,
                leases: 0,
                error: Some(error.to_string()),
            },
        };
        let native_approval_available = native_approval::is_available();
        let touch_id_enrolled = if native_approval_available {
            native_approval::status()
                .await
                .is_ok_and(|status| status.touch_id_enrolled)
        } else {
            false
        };
        AppSnapshot {
            daemon,
            vault_exists,
            skill_ready: sloosh::cli::embedded_skill_ready().unwrap_or(false),
            native_approval_available,
            touch_id_enrolled,
            pin: PinStore::current_user().status().into(),
            vault_unlock: self.unlock_snapshot(),
            vault_timeout_minutes: configured_vault_timeout().minutes(),
            cli_path: self.daemon_executable.display().to_string(),
        }
    }

    fn unlock_snapshot(&self) -> VaultUnlockSnapshot {
        let timeout = configured_vault_timeout();
        let status = self
            .desktop_unlock
            .lock()
            .map(|mut session| {
                session.sync_idle_timeout(timeout.duration());
                session.status()
            })
            .unwrap_or(UnlockStatus::Locked);
        VaultUnlockSnapshot::from_status(status, timeout)
    }

    fn unlock(&self, master_password: SecretString, method: UnlockMethod) -> Result<(), String> {
        self.desktop_unlock
            .lock()
            .map_err(|_| "Desktop unlock session is unavailable.".to_string())?
            .unlock(master_password, method);
        Ok(())
    }

    fn lock(&self) {
        if let Ok(mut session) = self.desktop_unlock.lock() {
            session.lock();
        }
    }

    fn touch(&self) -> Result<VaultUnlockSnapshot, String> {
        self.desktop_unlock
            .lock()
            .map_err(|_| "Desktop unlock session is unavailable.".to_string())?
            .touch()
            .map_err(|error| error.to_string())?;
        Ok(self.unlock_snapshot())
    }

    fn master_password(&self) -> Result<SecretString, String> {
        self.desktop_unlock
            .lock()
            .map_err(|_| "Desktop unlock session is unavailable.".to_string())?
            .credential()
            .map_err(|error| error.to_string())
    }

    fn set_idle_timeout(&self, timeout: VaultTimeout) -> Result<(), String> {
        self.desktop_unlock
            .lock()
            .map_err(|_| "Desktop unlock session is unavailable.".to_string())?
            .set_idle_timeout(timeout.duration());
        Ok(())
    }
}

impl VaultUnlockSnapshot {
    fn from_status(status: UnlockStatus, timeout: VaultTimeout) -> Self {
        match status {
            UnlockStatus::Locked => Self {
                state: "locked",
                method: None,
                idle_remaining_secs: None,
                absolute_remaining_secs: None,
                idle_timeout_minutes: timeout.minutes(),
            },
            UnlockStatus::Unlocked {
                method,
                idle_remaining_secs,
                absolute_remaining_secs,
            } => Self {
                state: "unlocked",
                method: Some(match method {
                    UnlockMethod::MasterPassword => "master_password",
                    UnlockMethod::TouchId => "touch_id",
                    UnlockMethod::Pin => "pin",
                }),
                idle_remaining_secs: Some(idle_remaining_secs),
                absolute_remaining_secs: Some(absolute_remaining_secs),
                idle_timeout_minutes: timeout.minutes(),
            },
        }
    }
}

async fn prompt_master_password(purpose: &str) -> Result<SecretString, String> {
    native_approval::prompt_master_password(purpose, false)
        .await
        .map_err(|error| error.to_string())
}

async fn verify_master_password(purpose: &str) -> Result<SecretString, String> {
    let password = prompt_master_password(purpose).await?;
    vault::unlock(password.expose_secret().as_bytes()).map_err(|error| error.to_string())?;
    Ok(password)
}

fn verify_vault_password(password: &SecretString) -> Result<(), String> {
    vault::unlock(password.expose_secret().as_bytes())
        .map(drop)
        .map_err(|error| error.to_string())
}

async fn refreshed(controller: &Controller) -> Result<AppSnapshot, String> {
    Ok(controller.snapshot().await)
}

#[tauri::command]
async fn initialize_vault(controller: tauri::State<'_, Controller>) -> Result<AppSnapshot, String> {
    let controller = controller.inner().clone();
    if vault::exists() {
        return Err("The credential vault is already initialized.".into());
    }
    let password = native_approval::prompt_master_password("Create credential vault", true)
        .await
        .map_err(|error| error.to_string())?;
    let session_password = password.clone();
    match controller
        .client()
        .request(&Request::InitVault {
            master_password: password,
        })
        .await
        .map_err(|error| error.to_string())?
    {
        Response::Ok => {
            controller.unlock(session_password, UnlockMethod::MasterPassword)?;
            refreshed(&controller).await
        }
        Response::Error { message } => Err(message),
        response => Err(format!(
            "daemon returned an unexpected response: {response:?}"
        )),
    }
}

#[tauri::command]
async fn install_skill(controller: tauri::State<'_, Controller>) -> Result<AppSnapshot, String> {
    let controller = controller.inner().clone();
    if !sloosh::cli::install_embedded_skill().map_err(|error| error.to_string())? {
        return Err(
            "An existing modified or externally managed Skill was preserved. Review it with the CLI."
                .into(),
        );
    }
    refreshed(&controller).await
}

#[tauri::command]
async fn enable_touch_id(controller: tauri::State<'_, Controller>) -> Result<AppSnapshot, String> {
    let controller = controller.inner().clone();
    let password = verify_master_password("Enable Touch ID").await?;
    native_approval::enroll(&password)
        .await
        .map_err(|error| error.to_string())?;
    controller.lock();
    refreshed(&controller).await
}

#[tauri::command]
async fn enable_pin(controller: tauri::State<'_, Controller>) -> Result<AppSnapshot, String> {
    let controller = controller.inner().clone();
    let password = verify_master_password("Enable approval PIN").await?;
    let pin = native_approval::prompt_pin()
        .await
        .map_err(|error| error.to_string())?;
    native_approval::store_pin_credential(&password)
        .await
        .map_err(|error| error.to_string())?;
    let store = PinStore::current_user();
    if let Err(error) = store.enroll(&pin) {
        let _ = native_approval::remove_pin_credential().await;
        return Err(error.to_string());
    }
    controller.lock();
    refreshed(&controller).await
}

#[tauri::command]
async fn disable_pin(controller: tauri::State<'_, Controller>) -> Result<AppSnapshot, String> {
    let controller = controller.inner().clone();
    let _password = verify_master_password("Disable approval PIN").await?;
    native_approval::remove_pin_credential()
        .await
        .map_err(|error| error.to_string())?;
    PinStore::current_user()
        .remove()
        .map_err(|error| error.to_string())?;
    controller.lock();
    refreshed(&controller).await
}

#[tauri::command]
async fn unlock_vault_with_master(
    controller: tauri::State<'_, Controller>,
) -> Result<VaultUnlockSnapshot, String> {
    let controller = controller.inner().clone();
    let password = prompt_master_password("Unlock Sloosh").await?;
    verify_vault_password(&password)?;
    controller.unlock(password, UnlockMethod::MasterPassword)?;
    Ok(controller.unlock_snapshot())
}

#[tauri::command]
async fn unlock_vault_with_touch_id(
    controller: tauri::State<'_, Controller>,
) -> Result<VaultUnlockSnapshot, String> {
    let controller = controller.inner().clone();
    let password = native_approval::unlock_with_touch_id()
        .await
        .map_err(|error| error.to_string())?;
    verify_vault_password(&password)?;
    controller.unlock(password, UnlockMethod::TouchId)?;
    Ok(controller.unlock_snapshot())
}

#[tauri::command]
async fn unlock_vault_with_pin(
    controller: tauri::State<'_, Controller>,
) -> Result<VaultUnlockSnapshot, String> {
    let controller = controller.inner().clone();
    let password = native_approval::unlock_with_pin()
        .await
        .map_err(|error| error.to_string())?;
    verify_vault_password(&password)?;
    controller.unlock(password, UnlockMethod::Pin)?;
    Ok(controller.unlock_snapshot())
}

#[tauri::command]
async fn lock_vault(
    controller: tauri::State<'_, Controller>,
) -> Result<VaultUnlockSnapshot, String> {
    let controller = controller.inner().clone();
    controller.lock();
    Ok(controller.unlock_snapshot())
}

#[tauri::command]
async fn get_vault_unlock_status(
    controller: tauri::State<'_, Controller>,
) -> Result<VaultUnlockSnapshot, String> {
    Ok(controller.unlock_snapshot())
}

#[tauri::command]
async fn touch_vault_session(
    controller: tauri::State<'_, Controller>,
) -> Result<VaultUnlockSnapshot, String> {
    controller.touch()
}

#[tauri::command]
async fn set_vault_timeout(
    controller: tauri::State<'_, Controller>,
    minutes: u16,
) -> Result<AppSnapshot, String> {
    let controller = controller.inner().clone();
    let timeout = VaultTimeout::try_from(minutes).map_err(|error| error.to_string())?;
    VaultSettingsStore::current_user()
        .save(timeout)
        .map_err(|error| error.to_string())?;
    controller.set_idle_timeout(timeout)?;
    refreshed(&controller).await
}

#[tauri::command]
async fn get_app_snapshot(controller: tauri::State<'_, Controller>) -> Result<AppSnapshot, String> {
    let controller = controller.inner().clone();
    Ok(controller.snapshot().await)
}

#[cfg_attr(debug_assertions, allow(dead_code))]
fn bundled_cli_path(current_executable: &Path) -> Option<PathBuf> {
    let macos = current_executable.parent()?;
    let contents = macos.parent()?;
    Some(contents.join("Helpers").join("sloosh"))
}

fn daemon_executable() -> Result<PathBuf, String> {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("SLOOSH_GUI_DAEMON") {
        return Ok(PathBuf::from(path));
    }

    #[cfg(debug_assertions)]
    {
        Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("target/debug/sloosh"))
    }

    #[cfg(not(debug_assertions))]
    {
        let current = std::env::current_exe().map_err(|error| error.to_string())?;
        bundled_cli_path(&current).ok_or_else(|| "could not locate bundled sloosh CLI".to_string())
    }
}

fn configured_vault_timeout() -> VaultTimeout {
    VaultSettingsStore::current_user()
        .load()
        .unwrap_or_else(|_| VaultTimeout::minimum())
}

fn main() {
    let vault_timeout = configured_vault_timeout();
    let controller = Controller {
        daemon_executable: daemon_executable().expect("resolve bundled sloosh CLI"),
        desktop_unlock: Arc::new(Mutex::new(DesktopUnlockSession::new(
            vault_timeout.duration(),
            DEFAULT_ABSOLUTE_TIMEOUT,
        ))),
    };
    system_lock::install(controller.clone());
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(controller)
        .invoke_handler(tauri::generate_handler![
            get_app_snapshot,
            install_skill,
            initialize_vault,
            enable_touch_id,
            enable_pin,
            disable_pin,
            unlock_vault_with_master,
            unlock_vault_with_touch_id,
            unlock_vault_with_pin,
            lock_vault,
            get_vault_unlock_status,
            touch_vault_session,
            set_vault_timeout,
            list_hosts,
            add_host,
            update_host,
            remove_host
        ])
        .build(tauri::generate_context!())
        .expect("build Sloosh desktop app");
    app.run(|app_handle, event| dock_icon::handle_run_event(app_handle, &event));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_cli_is_a_stable_helper_path() {
        let app = Path::new("/Applications/Sloosh.app/Contents/MacOS/Sloosh");
        assert_eq!(
            bundled_cli_path(app),
            Some(PathBuf::from(
                "/Applications/Sloosh.app/Contents/Helpers/sloosh"
            ))
        );
    }
}
