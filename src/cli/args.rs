//! Clap argument definitions for the implemented command surface
//! (docs/internals/architecture.md). Keep this help aligned with enforced security limits.

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "sloosh",
    version,
    about = "SSH-in-the-loop: persistent remote shells + human-approved credential access for coding agents",
    long_about = "sloosh gives a coding agent persistent SSH shells (cwd/env/background jobs survive \
across calls) while keeping credentials out of the agent's reach: connecting to a host requires a \
human to approve a lease out-of-band. Run `sloosh status` any time you're unsure what's going on."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Set up the Agent Skill and credential vault (interactive, human-only).
    Init(InitArgs),
    /// Install or inspect the embedded sloosh Agent Skill.
    Skill(SkillArgs),
    /// Run a command in a host's default (or named) session, blocking until it finishes or times out.
    Run(RunArgs),
    /// Fetch output a session has produced since the last peek.
    Peek(PeekArgs),
    /// Send raw keystrokes to a session's PTY (e.g. to answer an interactive prompt).
    Send(SendArgs),
    /// Send Ctrl-C to a session.
    Interrupt(InterruptArgs),
    /// Explicitly open a new named parallel session on a host.
    Open(OpenArgs),
    /// List known sessions and their state.
    Ls(LsArgs),
    /// Kill a session (terminates the remote shell).
    Kill(KillArgs),
    /// Request an access lease for one or more hosts (agent side of authorization).
    Request(RequestArgs),
    /// Approve a pending lease request (human side, run in another terminal).
    Approve(ApproveArgs),
    /// Manage vault-backed SSH hosts (interactive, human-only).
    Host(HostArgs),
    /// Add a credential to the vault. Interactive and human-only: there is no flag to pass a secret.
    /// Kept for compatibility; prefer `sloosh host add`.
    Add(AddArgs),
    /// Remove a credential from the vault.
    /// Kept for compatibility; prefer `sloosh host rm`.
    Rm(RmArgs),
    /// Manage the credential vault itself (e.g. first-time initialization).
    Vault(VaultArgs),
    /// Upload a local file to a host over SFTP.
    Put(PutArgs),
    /// Download a remote file from a host over SFTP.
    Get(GetArgs),
    /// Open an `-L` or `-R` forward, or manage active ones (`ls`/`stop`).
    Forward(ForwardArgs),
    /// Show daemon/session/lease status — the anchor command when unsure what's going on.
    Status(StatusArgs),
    /// Manage the sloosh daemon process directly (normally auto-started on demand).
    Daemon(DaemonArgs),
    /// Show the audit log.
    Log(LogArgs),
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Host alias to run the command on (as configured via `sloosh host add` / `~/.ssh/config`).
    pub host: String,
    /// Command to run in the remote shell.
    pub command: String,
    /// Use a named parallel session instead of the host's default session.
    #[arg(long)]
    pub session: Option<String>,
    /// Give up waiting after this many seconds and return a `running` status (does not kill the command).
    #[arg(long, default_value_t = 60)]
    pub timeout: u64,
    /// Skip ANSI-escape stripping and return the raw PTY output.
    #[arg(long)]
    pub raw: bool,
    /// Print machine-readable JSON instead of a human summary.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct PeekArgs {
    /// Host whose session to peek at.
    pub host: String,
    /// Named parallel session, if not using the host's default session.
    #[arg(long)]
    pub session: Option<String>,
    /// Return the last N bytes instead of only what's new since the last peek.
    #[arg(long)]
    pub tail: Option<usize>,
    /// Skip ANSI-escape stripping and return the raw PTY output.
    #[arg(long)]
    pub raw: bool,
    /// Print machine-readable JSON instead of a human summary.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct SendArgs {
    /// Host whose session to send keys to.
    pub host: String,
    /// Literal text/keystrokes to write to the PTY (e.g. "y\n").
    pub keys: String,
    /// Named parallel session, if not using the host's default session.
    #[arg(long)]
    pub session: Option<String>,
    /// Append a newline after the keys (equivalent to pressing Enter).
    #[arg(long)]
    pub newline: bool,
}

#[derive(Debug, Args)]
pub struct InterruptArgs {
    /// Host whose session to interrupt.
    pub host: String,
    /// Named parallel session, if not using the host's default session.
    #[arg(long)]
    pub session: Option<String>,
}

#[derive(Debug, Args)]
pub struct OpenArgs {
    /// Host to open a session on.
    pub host: String,
    /// Name for the new parallel session.
    pub name: String,
}

#[derive(Debug, Args)]
pub struct LsArgs {
    /// Only list sessions for this host.
    #[arg(long)]
    pub host: Option<String>,
    /// Print machine-readable JSON instead of a human summary.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct KillArgs {
    /// Host whose session to kill.
    pub host: String,
    /// Named parallel session, if not using the host's default session.
    #[arg(long)]
    pub session: Option<String>,
}

#[derive(Debug, Args)]
pub struct RequestArgs {
    /// Hosts to request access to (leases are scoped by host, never global).
    #[arg(required = true)]
    pub hosts: Vec<String>,
}

#[derive(Debug, Args)]
pub struct ApproveArgs {
    /// Request ID printed by `sloosh request` (paste it here, in another terminal).
    pub request_id: String,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Alias the agent will refer to this credential by (never the credential itself).
    pub alias: String,
    /// Real hostname/address to connect to.
    #[arg(long)]
    pub hostname: String,
    /// Remote username (defaults to the local user if omitted).
    #[arg(long)]
    pub user: Option<String>,
    /// SSH port (defaults to 22 if omitted).
    #[arg(long)]
    pub port: Option<u16>,
    /// Authentication method for this profile.
    #[arg(long, value_enum, default_value_t = HostAuthArg::Password)]
    pub auth: HostAuthArg,
    /// Unencrypted Ed25519/ECDSA key path. Encrypted or RSA keys must use ssh-agent.
    #[arg(long, required_if_eq("auth", "key-file"))]
    pub key_file: Option<String>,
    /// Route through another managed host profile.
    #[arg(long, conflicts_with_all = ["proxy_jump", "jump"])]
    pub via: Option<String>,
    /// Advanced OpenSSH ProxyJump specification.
    #[arg(long, conflicts_with_all = ["via", "jump"])]
    pub proxy_jump: Option<String>,
    /// Jump host alias to reach this host through (resolvable via the vault
    /// or ~/.ssh/config). Deprecated; use --via or --proxy-jump.
    #[arg(long, conflicts_with_all = ["via", "proxy_jump"])]
    pub jump: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HostAuthArg {
    Agent,
    Password,
    KeyFile,
}

#[derive(Debug, Args)]
pub struct RmArgs {
    /// Alias of the credential to remove.
    pub alias: String,
}

#[derive(Debug, Args)]
pub struct HostArgs {
    #[command(subcommand)]
    pub action: HostAction,
}

#[derive(Debug, Subcommand)]
pub enum HostAction {
    /// List vault-backed hosts without exposing authentication material.
    #[command(alias = "ls")]
    List(HostListArgs),
    /// Show one vault-backed host without exposing authentication material.
    Show(HostShowArgs),
    /// Add a vault-backed host.
    Add(AddArgs),
    /// Edit an existing vault-backed host. Alias cannot be changed.
    Edit(HostEditArgs),
    /// Inspect and explicitly trust a new or changed remote host key.
    Trust(HostTrustArgs),
    /// Remove a vault-backed host.
    Rm(RmArgs),
}

#[derive(Debug, Args)]
pub struct HostListArgs {
    /// Print machine-readable JSON instead of a table.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct HostShowArgs {
    /// Alias of the vault-backed host to show.
    pub alias: String,
    /// Print machine-readable JSON instead of labeled fields.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct HostTrustArgs {
    /// Vault-backed host alias whose route should be checked dependency-first.
    pub alias: String,
}

#[derive(Debug, Args)]
pub struct HostEditArgs {
    /// Alias of the vault-backed host to edit. Aliases are immutable.
    pub alias: String,
    /// Replace the real hostname/address.
    #[arg(long)]
    pub hostname: Option<String>,
    /// Replace the remote username.
    #[arg(long, conflicts_with = "clear_user")]
    pub user: Option<String>,
    /// Clear the configured remote username.
    #[arg(long)]
    pub clear_user: bool,
    /// Replace the SSH port.
    #[arg(long, conflicts_with = "clear_port")]
    pub port: Option<u16>,
    /// Clear the configured port and use SSH's default.
    #[arg(long)]
    pub clear_port: bool,
    /// Replace the authentication method.
    #[arg(long, value_enum)]
    pub auth: Option<HostAuthArg>,
    /// Unencrypted Ed25519/ECDSA key path. Encrypted or RSA keys must use ssh-agent.
    #[arg(long, required_if_eq("auth", "key-file"))]
    pub key_file: Option<String>,
    /// Route through another managed host profile.
    #[arg(long, conflicts_with_all = ["proxy_jump", "jump", "direct", "clear_jump"])]
    pub via: Option<String>,
    /// Advanced OpenSSH ProxyJump specification.
    #[arg(long, conflicts_with_all = ["via", "jump", "direct", "clear_jump"])]
    pub proxy_jump: Option<String>,
    /// Connect directly and clear the current route.
    #[arg(long, conflicts_with_all = ["via", "proxy_jump", "jump", "clear_jump"])]
    pub direct: bool,
    /// Replace the ProxyJump alias.
    #[arg(long, conflicts_with_all = ["clear_jump", "via", "proxy_jump", "direct"])]
    pub jump: Option<String>,
    /// Clear the configured ProxyJump alias.
    #[arg(long, conflicts_with_all = ["via", "proxy_jump", "direct", "jump"])]
    pub clear_jump: bool,
    /// Securely prompt for and replace the SSH password. Deprecated; use --auth password.
    #[arg(long, conflicts_with = "auth")]
    pub change_password: bool,
}

#[derive(Debug, Args)]
pub struct VaultArgs {
    #[command(subcommand)]
    pub action: VaultAction,
}

#[derive(Debug, Subcommand)]
pub enum VaultAction {
    /// Create the credential vault and set its master password (interactive, human-only).
    /// Required once before any `sloosh approve` can succeed: approval never creates the vault.
    Init,
    /// Show or set the shared desktop-vault and idle lease timeout.
    Timeout(VaultTimeoutArgs),
}

#[derive(Debug, Args)]
pub struct VaultTimeoutArgs {
    /// Idle timeout in minutes. Supported values: 1, 5, 15, 30.
    pub minutes: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SkillAgent {
    /// Detect installed agents; default to the portable Codex-compatible path.
    Auto,
    /// Install under ~/.agents/skills for Codex and other Agent Skills readers.
    Codex,
    /// Install under ~/.claude/skills for Claude Code.
    Claude,
    /// Install for both Codex-compatible agents and Claude Code.
    All,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Agent installation to configure.
    #[arg(long, value_enum, default_value_t = SkillAgent::Auto)]
    pub agent: SkillAgent,
    /// Replace an externally managed or locally modified Skill.
    #[arg(long = "force-skill")]
    pub force_skill: bool,
}

#[derive(Debug, Args)]
pub struct SkillArgs {
    #[command(subcommand)]
    pub action: SkillAction,
}

#[derive(Debug, Subcommand)]
pub enum SkillAction {
    /// Install or update the Skill embedded in this sloosh binary.
    Install(SkillInstallArgs),
    /// Report the installed Skill's source and update state.
    Status(SkillStatusArgs),
}

#[derive(Debug, Args)]
pub struct SkillInstallArgs {
    /// Agent installation to configure.
    #[arg(long, value_enum, default_value_t = SkillAgent::Auto)]
    pub agent: SkillAgent,
    /// Replace an externally managed or locally modified Skill.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct SkillStatusArgs {
    /// Agent installation to inspect.
    #[arg(long, value_enum, default_value_t = SkillAgent::Auto)]
    pub agent: SkillAgent,
}

#[derive(Debug, Args)]
#[command(
    long_about = "Upload a local file to a host over SFTP, reusing the session's existing SSH \
connection (no redial, no reauth). An existing file at the remote path is always overwritten: \
the remote host is the disposable workspace, so `put` doesn't ask. The transfer is streamed in \
bounded chunks and has no total file-size limit."
)]
pub struct PutArgs {
    /// Destination host.
    pub host: String,
    /// Local file path to upload.
    pub local_path: String,
    /// Destination path on the remote host.
    pub remote_path: String,
    /// Named parallel session whose connection to reuse.
    #[arg(long)]
    pub session: Option<String>,
}

#[derive(Debug, Args)]
#[command(
    long_about = "Download a remote file from a host over SFTP, reusing the session's existing \
SSH connection (no redial, no reauth). Unlike `put`, an existing file at the local destination \
is left alone unless you pass --force: the remote host is a disposable workspace, but your local \
machine is not, so `get` refuses to clobber it by default. The download is streamed to a \
same-directory temporary file using the caller's umask and atomically committed only after \
success; total file size is not capped."
)]
pub struct GetArgs {
    /// Source host.
    pub host: String,
    /// Remote file path to download.
    pub remote_path: String,
    /// Local destination path.
    pub local_path: String,
    /// Named parallel session whose connection to reuse.
    #[arg(long)]
    pub session: Option<String>,
    /// Overwrite an existing local file at the destination path.
    #[arg(long)]
    pub force: bool,
}

/// `forward` doesn't have a fixed keyword for its "open a tunnel" form
/// (`sloosh forward <host> -L ...`, mirroring `ssh -L`'s own syntax) — only
/// `ls`/`stop` are real subcommand keywords. Anything else is treated as
/// `<host> -L/-R spec`, re-parsed by [`ForwardOpenArgs`] via clap's
/// `external_subcommand` escape hatch (see `Command::Forward`'s dispatch in
/// `cli::mod`).
#[derive(Debug, Args)]
#[command(
    after_help = "Open a forward:\n  sloosh forward <host> -L <SPEC>\n  sloosh forward <host> -R <SPEC>\n\nManage active forwards with `sloosh forward ls` and `sloosh forward stop <ID>`."
)]
pub struct ForwardArgs {
    #[command(subcommand)]
    pub action: ForwardAction,
}

#[derive(Debug, Subcommand)]
pub enum ForwardAction {
    /// List active forwards.
    Ls(ForwardLsArgs),
    /// Stop an active forward.
    Stop(ForwardStopArgs),
    /// `<host> -L ...` or `<host> -R ...` — not a real keyword; clap hands us
    /// the raw tokens and `cli::mod` re-parses them.
    #[command(external_subcommand)]
    Open(Vec<String>),
}

#[derive(Debug, Parser)]
#[command(
    name = "sloosh forward",
    no_binary_name = true,
    group(ArgGroup::new("direction").args(["local", "remote"]).required(true))
)]
pub struct ForwardOpenArgs {
    /// Host to forward through (as configured via `sloosh host add` / `~/.ssh/config`).
    pub host: String,
    /// Local forward: listen on a loopback address and tunnel to
    /// remote_host:remote_port via `host`. `[bind_addr:]local_port:remote_host:remote_port`
    /// (bind_addr defaults to 127.0.0.1 and must be loopback; local_port 0 asks the OS
    /// to pick a port).
    #[arg(short = 'L', long = "local", value_name = "SPEC")]
    pub local: Option<String>,
    /// Remote (reverse) forward: listen on the SSH server and tunnel to
    /// local_host:local_port. `[bind_addr:]remote_port:local_host:local_port`
    /// (bind_addr defaults to 127.0.0.1; remote_port 0 asks the server to pick a port).
    /// The server's GatewayPorts policy decides whether that listener is reachable
    /// beyond its loopback interface.
    #[arg(short = 'R', long = "remote", value_name = "SPEC")]
    pub remote: Option<String>,
    /// Print machine-readable JSON instead of a human summary.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ForwardLsArgs {
    /// Print machine-readable JSON instead of a human summary.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ForwardStopArgs {
    /// Forward id printed when opening `-L`/`-R` (also shown by `forward ls`).
    pub id: String,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Print machine-readable JSON instead of a human summary.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct DaemonArgs {
    #[command(subcommand)]
    pub action: DaemonAction,
}

#[derive(Debug, Subcommand)]
pub enum DaemonAction {
    /// Start the daemon in the background if it isn't already running.
    Start,
    /// Ask a running daemon to shut down.
    Stop,
    /// Report whether the daemon is running, without auto-starting it.
    Status,
}

#[derive(Debug, Args)]
pub struct LogArgs {
    /// Only show entries for this host.
    #[arg(long)]
    pub host: Option<String>,
    /// Number of most-recent entries to show.
    #[arg(short = 'n', long = "count", default_value_t = 50)]
    pub count: usize,
    /// Print raw NDJSON lines instead of a human-readable summary.
    #[arg(long)]
    pub json: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn forward_help_documents_open_and_management_forms() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("forward")
            .expect("forward subcommand")
            .render_help()
            .to_string();

        assert!(help.contains("sloosh forward <host> -L <SPEC>"), "{help}");
        assert!(help.contains("sloosh forward <host> -R <SPEC>"), "{help}");
        assert!(
            help.contains(
                "Manage active forwards with `sloosh forward ls` and `sloosh forward stop <ID>`."
            ),
            "{help}"
        );
    }

    #[test]
    fn onboarding_help_exposes_agents_and_force_boundaries() {
        let mut command = Cli::command();
        let init_help = command
            .find_subcommand_mut("init")
            .expect("init subcommand")
            .render_help()
            .to_string();
        assert!(init_help.contains("--agent <AGENT>"), "{init_help}");
        assert!(init_help.contains("--force-skill"), "{init_help}");

        let skill = command
            .find_subcommand_mut("skill")
            .expect("skill subcommand");
        let install_help = skill
            .find_subcommand_mut("install")
            .expect("skill install subcommand")
            .render_help()
            .to_string();
        assert!(install_help.contains("--agent <AGENT>"), "{install_help}");
        assert!(install_help.contains("auto"), "{install_help}");
        assert!(install_help.contains("codex"), "{install_help}");
        assert!(install_help.contains("claude"), "{install_help}");
        assert!(install_help.contains("all"), "{install_help}");
        assert!(install_help.contains("--force"), "{install_help}");
    }

    #[test]
    fn host_help_exposes_complete_management_surface_and_legacy_commands() {
        let mut command = Cli::command();
        let host = command
            .find_subcommand_mut("host")
            .expect("host subcommand");
        for action in ["list", "show", "add", "edit", "trust", "rm"] {
            assert!(
                host.find_subcommand_mut(action).is_some(),
                "missing host {action}"
            );
        }
        let edit_help = host
            .find_subcommand_mut("edit")
            .expect("host edit subcommand")
            .render_help()
            .to_string();
        assert!(edit_help.contains("--change-password"), "{edit_help}");
        assert!(edit_help.contains("--auth <AUTH>"), "{edit_help}");
        assert!(edit_help.contains("--key-file <KEY_FILE>"), "{edit_help}");
        assert!(edit_help.contains("--via <VIA>"), "{edit_help}");
        assert!(
            edit_help.contains("--proxy-jump <PROXY_JUMP>"),
            "{edit_help}"
        );
        assert!(edit_help.contains("--clear-user"), "{edit_help}");
        assert!(edit_help.contains("--clear-port"), "{edit_help}");
        assert!(edit_help.contains("--clear-jump"), "{edit_help}");

        assert!(command.find_subcommand_mut("add").is_some());
        assert!(command.find_subcommand_mut("rm").is_some());
    }

    #[test]
    fn host_add_requires_key_path_and_routes_are_exclusive() {
        let missing_key = Cli::try_parse_from([
            "sloosh",
            "host",
            "add",
            "web",
            "--hostname",
            "web.example",
            "--auth",
            "key-file",
        ]);
        assert!(missing_key.is_err());

        let conflicting_route = Cli::try_parse_from([
            "sloosh",
            "host",
            "add",
            "web",
            "--hostname",
            "web.example",
            "--via",
            "bastion",
            "--proxy-jump",
            "edge",
        ]);
        assert!(conflicting_route.is_err());

        let valid = Cli::try_parse_from([
            "sloosh",
            "host",
            "add",
            "web",
            "--hostname",
            "web.example",
            "--auth",
            "agent",
            "--via",
            "bastion",
        ]);
        assert!(valid.is_ok());
    }

    #[test]
    fn vault_timeout_accepts_show_and_set_forms() {
        assert!(Cli::try_parse_from(["sloosh", "vault", "timeout"]).is_ok());
        assert!(Cli::try_parse_from(["sloosh", "vault", "timeout", "5"]).is_ok());
    }

    #[test]
    fn daemon_run_is_not_a_public_cli_command() {
        assert!(Cli::try_parse_from(["sloosh", "daemon", "run"]).is_err());
        assert!(Cli::try_parse_from(["sloosh", "daemon", "start"]).is_ok());
        assert!(Cli::try_parse_from(["sloosh", "daemon", "stop"]).is_ok());
        assert!(Cli::try_parse_from(["sloosh", "daemon", "status"]).is_ok());
    }
}
