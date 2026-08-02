//! CLI: clap command definitions, client-side dispatch, daemon auto-spawn
//! (docs/internals/architecture.md).

mod approval;
mod args;
pub mod client;
mod daemon_cmd;
mod forward;
mod host;
mod log;
mod session;
mod skill;
mod transfer;

pub use args::Cli;
use args::{
    Command, HostAction, InitArgs, SkillAction, SkillAgent, SkillInstallArgs, SkillStatusArgs,
    VaultAction, VaultTimeoutArgs,
};

#[cfg(test)]
use crate::proto::{self, HostRoute, HostSummary};
use crate::proto::{Request, Response};
use crate::transport::Channel;
use crate::transport::unix;
use std::path::Path;

use approval::{
    cmd_approve, cmd_request, cmd_vault_init_inner, display_host_list, prompt_master_password,
    require_tty,
};
use daemon_cmd::{cmd_daemon, cmd_status};
#[cfg(test)]
use daemon_cmd::{daemon_connect_error, daemon_is_not_running_error};
use forward::cmd_forward;
use host::{cmd_add, cmd_host_edit, cmd_host_list, cmd_host_show, cmd_host_trust, cmd_rm};
#[cfg(test)]
use host::{display_host_endpoint, escape_terminal_controls};
use log::cmd_log;
#[cfg(test)]
use log::render_field_value;
use session::{cmd_interrupt, cmd_kill, cmd_ls, cmd_open, cmd_peek, cmd_run, cmd_send};
#[cfg(test)]
use transfer::{LocalDownload, open_local_upload, resolve_local_path};
use transfer::{cmd_get, cmd_put};

/// Run the parsed CLI command. Errors are rendered by `main` and always
/// exit non-zero; nothing in here panics or uses `todo!()`.
pub async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Init(args) => cmd_init(args).await,
        Command::Skill(args) => cmd_skill(args.action),
        Command::Status(args) => cmd_status(args).await,
        Command::Daemon(args) => cmd_daemon(args.action).await,

        Command::Run(args) => cmd_run(args).await,
        Command::Peek(args) => cmd_peek(args).await,
        Command::Send(args) => cmd_send(args).await,
        Command::Interrupt(args) => cmd_interrupt(args).await,
        Command::Open(args) => cmd_open(args).await,
        Command::Ls(args) => cmd_ls(args).await,
        Command::Kill(args) => cmd_kill(args).await,
        Command::Request(args) => cmd_request(args).await,
        Command::Approve(args) => cmd_approve(args).await,
        Command::Host(args) => match args.action {
            HostAction::List(args) => cmd_host_list(args).await,
            HostAction::Show(args) => cmd_host_show(args).await,
            HostAction::Add(args) => cmd_add(args).await,
            HostAction::Edit(args) => cmd_host_edit(args).await,
            HostAction::Trust(args) => cmd_host_trust(args).await,
            HostAction::Rm(args) => cmd_rm(args).await,
        },
        Command::Add(args) => cmd_add(args).await,
        Command::Rm(args) => cmd_rm(args).await,
        Command::Vault(args) => match args.action {
            VaultAction::Init => cmd_vault_init().await,
            VaultAction::Timeout(args) => cmd_vault_timeout(args),
        },
        Command::Put(args) => cmd_put(args).await,
        Command::Get(args) => cmd_get(args).await,
        Command::Forward(args) => cmd_forward(args.action).await,
        Command::Log(args) => cmd_log(args).await,
    }
}

fn cmd_vault_timeout(args: VaultTimeoutArgs) -> anyhow::Result<()> {
    use crate::vault_settings::{VaultSettingsStore, VaultTimeout};

    let store = VaultSettingsStore::current_user();
    let timeout = match args.minutes {
        Some(minutes) => {
            let timeout = VaultTimeout::try_from(minutes)?;
            store.save(timeout)?;
            timeout
        }
        None => store.load()?,
    };
    println!(
        "vault timeout: {} minute{}",
        timeout.minutes(),
        if timeout.minutes() == 1 { "" } else { "s" }
    );
    Ok(())
}

/// `SLOOSH_LEASE` escape-hatch token from the environment, if this process
/// has one set (docs/internals/architecture.md) — forwarded on every host-touching request so
/// the daemon can check it before falling back to ancestry matching.
fn lease_token_from_env() -> Option<String> {
    std::env::var("SLOOSH_LEASE").ok()
}

/// Connect (auto-spawning the daemon if needed) and send one request,
/// returning the raw response. All the new session commands share this
/// shape; only the response-matching differs per command.
async fn send_request(req: &Request) -> anyhow::Result<Response> {
    let socket_path = unix::resolve_socket_path();
    let mut chan = client::connect_or_spawn(&socket_path).await?;
    chan.send(req).await?;
    match chan.recv().await? {
        Some(resp) => Ok(resp),
        None => anyhow::bail!(
            "daemon closed the connection without responding; check ~/.sloosh/daemon.log for a crash"
        ),
    }
}

fn bail_on_error_or_unexpected(resp: Response) -> anyhow::Result<Response> {
    if let Response::Error { message } = &resp {
        anyhow::bail!("daemon reported an error: {message}");
    }
    Ok(resp)
}

async fn cmd_vault_init() -> anyhow::Result<()> {
    require_tty("vault init")?;
    explain_cli_approval_setup();
    let _ = cmd_vault_init_inner().await?;
    Ok(())
}

async fn cmd_init(args: InitArgs) -> anyhow::Result<()> {
    require_tty("init")?;
    cmd_skill_install(SkillInstallArgs {
        agent: args.agent,
        force: args.force_skill,
    })?;
    explain_cli_approval_setup();
    let _ = cmd_vault_init_inner().await?;
    Ok(())
}

const CLI_APPROVAL_SETUP: &str = "Approval setup:\n  Scopes using only the default system SSH agent, with no key-file fallback, authorize automatically. Approve every other pending lease from another human terminal with the printed `sloosh approve <ID>` command.\n  On macOS, the optional Sloosh desktop app owns login Keychain, Touch ID, and PIN enrollment in its Setup and Security screens. The CLI does not launch the native helper.";

fn cli_approval_setup_message() -> &'static str {
    CLI_APPROVAL_SETUP
}

fn explain_cli_approval_setup() {
    println!("{}", cli_approval_setup_message());
}

fn cmd_skill(action: SkillAction) -> anyhow::Result<()> {
    match action {
        SkillAction::Install(args) => cmd_skill_install(args),
        SkillAction::Status(args) => cmd_skill_status(args),
    }
}

fn cmd_skill_install(args: SkillInstallArgs) -> anyhow::Result<()> {
    for target in skill_targets(args.agent)? {
        let outcome = skill::install_target(&target, args.force)?;
        let path = target.directory.display();
        match outcome {
            skill::InstallOutcome::Installed => {
                println!("installed sloosh Skill for {} at {path}", target.agent);
            }
            skill::InstallOutcome::Current => {
                println!("sloosh Skill for {} is current at {path}", target.agent);
            }
            skill::InstallOutcome::CurrentExternal => {
                println!(
                    "externally managed Skill for {} already matches this sloosh version at {path}",
                    target.agent
                );
            }
            skill::InstallOutcome::Updated => {
                println!("updated sloosh Skill for {} at {path}", target.agent);
            }
            skill::InstallOutcome::PreservedExternal => {
                println!(
                    "kept externally managed Skill for {} at {path}; use --force to replace it",
                    target.agent
                );
            }
            skill::InstallOutcome::PreservedModified => {
                println!(
                    "kept locally modified sloosh Skill for {} at {path}; use --force to replace it",
                    target.agent
                );
            }
        }
    }
    Ok(())
}

fn cmd_skill_status(args: SkillStatusArgs) -> anyhow::Result<()> {
    for target in skill_targets(args.agent)? {
        let state = match skill::inspect_target(&target)? {
            skill::SkillStatus::Missing => "missing",
            skill::SkillStatus::CurrentManaged => "current (managed by sloosh)",
            skill::SkillStatus::CurrentExternal => "current (externally managed)",
            skill::SkillStatus::UpgradeAvailable => "upgrade available",
            skill::SkillStatus::Modified => "locally modified",
            skill::SkillStatus::External => "externally managed",
        };
        println!("{}: {state} ({})", target.agent, target.directory.display());
    }
    Ok(())
}

fn skill_targets(agent: SkillAgent) -> anyhow::Result<Vec<skill::SkillTarget>> {
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("HOME is not set; cannot locate the Agent Skill directory")
        })?;
    skill::resolve_targets_from_home(Path::new(&home), agent)
}

/// Read-only desktop seam for the embedded Skill's auto-detected targets.
pub fn embedded_skill_ready() -> anyhow::Result<bool> {
    Ok(skill_targets(SkillAgent::Auto)?.iter().all(|target| {
        matches!(
            skill::inspect_target(target),
            Ok(skill::SkillStatus::CurrentManaged | skill::SkillStatus::CurrentExternal)
        )
    }))
}

/// Install/update the embedded Skill without exposing a general process API.
pub fn install_embedded_skill() -> anyhow::Result<bool> {
    for target in skill_targets(SkillAgent::Auto)? {
        skill::install_target(&target, false)?;
    }
    embedded_skill_ready()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    // These tests deliberately never call `std::env::set_current_dir` (that
    // mutates process-global state and would race with every other test
    // running concurrently in this binary) — they only *read* the real
    // current directory to compute the expected answer, then check
    // `resolve_local_path` agrees with it.

    #[test]
    fn absolute_path_is_returned_unchanged() {
        let abs = if cfg!(windows) {
            "C:\\tmp\\thing.txt"
        } else {
            "/tmp/thing.txt"
        };
        assert_eq!(resolve_local_path(abs).unwrap(), abs);
    }

    #[test]
    fn relative_path_is_resolved_against_the_current_directory() {
        let cwd = std::env::current_dir().expect("current dir");
        let expected = cwd
            .join("some/relative/path.txt")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            resolve_local_path("some/relative/path.txt").unwrap(),
            expected
        );
    }

    #[test]
    fn bare_filename_is_resolved_against_the_current_directory() {
        let cwd = std::env::current_dir().expect("current dir");
        let expected = cwd.join("file.txt").to_string_lossy().into_owned();
        assert_eq!(resolve_local_path("file.txt").unwrap(), expected);
    }

    #[test]
    fn daemon_identity_refusal_is_not_reported_as_not_running() {
        let denied = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "server identity could not be verified",
        );
        assert!(!daemon_is_not_running_error(&denied));
        let message = daemon_connect_error(Path::new("/tmp/sloosh.sock"), denied).to_string();
        assert!(message.contains("refusing to use the daemon socket"));
        assert!(message.contains("server identity could not be verified"));
        assert!(message.contains("sloosh daemon stop"));

        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::ConnectionRefused,
        ] {
            assert!(daemon_is_not_running_error(&std::io::Error::new(
                kind,
                "daemon absent"
            )));
        }
        assert!(!daemon_is_not_running_error(&std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "connect timed out"
        )));
    }

    #[test]
    fn audit_string_fields_escape_terminal_controls() {
        let rendered = render_field_value(&serde_json::Value::String(
            "host\n\u{1b}[31mforged".to_string(),
        ));
        assert!(!rendered.contains('\n'));
        assert!(!rendered.contains('\u{1b}'));
        assert!(rendered.contains("\\n"));
        assert!(rendered.contains("\\u{1b}"));
    }

    #[test]
    fn legacy_host_metadata_escapes_terminal_controls() {
        let host = HostSummary {
            alias: "web\nforged".to_string(),
            hostname: "server\u{1b}[31m.example".to_string(),
            port: Some(22),
            user: Some("deploy\tadmin".to_string()),
            auth: proto::HostAuthKind::Agent,
            route: HostRoute::Direct,
        };

        assert_eq!(escape_terminal_controls(&host.alias), "web\\nforged");
        assert_eq!(display_host_endpoint(&host), "server\\u{1b}[31m.example:22");
        assert_eq!(
            escape_terminal_controls(host.user.as_deref().unwrap()),
            "deploy\\tadmin"
        );
    }

    #[test]
    fn cli_setup_routes_native_approval_to_the_desktop_app() {
        let message = cli_approval_setup_message();
        assert!(message.contains("login Keychain"));
        assert!(message.contains("desktop app"));
        assert!(message.contains("Setup and Security"));
        assert!(message.contains("does not launch the native helper"));
        assert!(message.contains("sloosh approve <ID>"));
        assert!(!message.contains("Touch ID approval enabled"));
    }

    fn transfer_test_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "sloosh-cli-transfer-{tag}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    #[tokio::test]
    async fn upload_file_is_opened_by_cli_without_total_size_limit() {
        let path = transfer_test_path("upload");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(128 * 1024 * 1024)
            .unwrap();
        let file = open_local_upload(path.to_str().unwrap()).await.unwrap();
        assert_eq!(file.metadata().await.unwrap().len(), 128 * 1024 * 1024);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn download_write_is_atomic_and_refuses_clobber_without_force() {
        let path = transfer_test_path("download");
        std::fs::write(&path, b"keep-me").unwrap();

        let err = match LocalDownload::open(&path, false).await {
            Ok(_) => panic!("existing destination should be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("--force"));
        assert_eq!(std::fs::read(&path).unwrap(), b"keep-me");

        let mut download = LocalDownload::open(&path, true).await.unwrap();
        download.write_chunk(b"replace").await.unwrap();
        download.write_chunk(b"ment").await.unwrap();
        download.finish().await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn download_mode_follows_caller_umask() {
        const CHILD_MARKER: &str = "SLOOSH_DOWNLOAD_UMASK_CHILD";
        const DESTINATION: &str = "SLOOSH_DOWNLOAD_UMASK_DESTINATION";

        if std::env::var_os(CHILD_MARKER).is_some() {
            let path = std::path::PathBuf::from(
                std::env::var_os(DESTINATION).expect("child destination path"),
            );
            let mut download = LocalDownload::open(&path, false).await.unwrap();
            download.write_chunk(b"umask").await.unwrap();
            download.finish().await.unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o640, "0666 creation mode under umask 027");

            let force_path = path.with_extension("force");
            std::fs::write(&force_path, b"old").unwrap();
            std::fs::set_permissions(&force_path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let mut forced = LocalDownload::open(&force_path, true).await.unwrap();
            forced.write_chunk(b"new").await.unwrap();
            forced.finish().await.unwrap();
            let force_mode = std::fs::metadata(&force_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(force_mode, 0o640, "forced replacement follows umask");

            let _ = std::fs::remove_file(path);
            let _ = std::fs::remove_file(force_path);
            return;
        }

        let path = transfer_test_path("download-umask");
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("umask 027; exec \"$@\"")
            .arg("sh")
            .arg(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("cli::tests::download_mode_follows_caller_umask")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .env(DESTINATION, &path)
            .status()
            .expect("run isolated-umask child test");
        assert!(status.success(), "isolated-umask child test failed");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn interrupted_download_removes_temp_without_creating_destination() {
        let path = transfer_test_path("interrupted-download");
        let _ = std::fs::remove_file(&path);

        let mut download = LocalDownload::open(&path, false).await.unwrap();
        download.write_chunk(b"partial bytes").await.unwrap();
        let temp = download.temp.clone();
        assert!(temp.exists());
        drop(download);

        assert!(!temp.exists(), "partial temp file must be removed");
        assert!(
            !path.exists(),
            "an interrupted download must not create the final destination"
        );
    }
}
