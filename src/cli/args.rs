//! Clap argument definitions for every phase-1 subcommand (DESIGN.md §6).
//!
//! Most of these commands aren't implemented yet (see `cli::dispatch`) —
//! the shapes here are the intended phase-1 surface so `--help` is useful
//! today and wiring them up later doesn't change the CLI contract.

use clap::{ArgGroup, Args, Parser, Subcommand};

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
    /// Add a credential to the vault. Interactive and human-only: there is no flag to pass a secret.
    Add(AddArgs),
    /// Remove a credential from the vault.
    Rm(RmArgs),
    /// Manage the credential vault itself (e.g. first-time initialization).
    Vault(VaultArgs),
    /// Upload a local file to a host over SFTP.
    Put(PutArgs),
    /// Download a remote file from a host over SFTP.
    Get(GetArgs),
    /// Open a `-L`/`-R` port forward through a host, or manage active ones (`ls`/`stop`).
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
    /// Host alias to run the command on (as configured via `sloosh add` / `~/.ssh/config`).
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
    /// Jump host alias to reach this host through (resolvable via the vault
    /// or ~/.ssh/config), same as an ~/.ssh/config `ProxyJump` entry.
    #[arg(long)]
    pub jump: Option<String>,
}

#[derive(Debug, Args)]
pub struct RmArgs {
    /// Alias of the credential to remove.
    pub alias: String,
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
}

#[derive(Debug, Args)]
#[command(
    long_about = "Upload a local file to a host over SFTP, reusing the session's existing SSH \
connection (no redial, no reauth). An existing file at the remote path is always overwritten: \
the remote host is the disposable workspace, so `put` doesn't ask."
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
machine is not, so `get` refuses to clobber it by default."
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
    /// `<host> -L ...` / `<host> -R ...` (see `ForwardOpenArgs`) — not a real
    /// keyword; clap hands us the raw tokens and `cli::mod` re-parses them.
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
    /// Host to forward through (as configured via `sloosh add` / `~/.ssh/config`).
    pub host: String,
    /// Local forward: listen locally, tunnel to remote_host:remote_port via `host`.
    /// `[bind_addr:]local_port:remote_host:remote_port` (bind_addr defaults to
    /// 127.0.0.1; local_port 0 asks the OS to pick a port).
    #[arg(short = 'L', long = "local", value_name = "SPEC")]
    pub local: Option<String>,
    /// Remote (reverse) forward: `host` listens and tunnels back to
    /// local_host:local_port on this machine.
    /// `[bind_addr:]remote_port:local_host:local_port`.
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
    /// Forward id printed by `sloosh forward <host> -L/-R ...` (also shown by `forward ls`).
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
    /// Run the daemon accept loop in the foreground (this is what `start`/auto-spawn exec).
    Run,
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
