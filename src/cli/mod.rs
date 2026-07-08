//! CLI: clap command definitions, client-side dispatch, daemon auto-spawn
//! (DESIGN.md §6, §8).

mod args;
mod client;

pub use args::Cli;
use args::{
    AddArgs, ApproveArgs, Command, DaemonAction, GetArgs, InterruptArgs, KillArgs, LogArgs, LsArgs,
    OpenArgs, PeekArgs, PutArgs, RequestArgs, RmArgs, RunArgs, SendArgs, StatusArgs, VaultAction,
};

use crate::daemon::audit;
use crate::daemon::ssh;
use crate::proto::{
    self, LeaseActivatedInfo, LeaseRequestSummary, PeekReply, Request, Response, RunReply,
    SecretString, SessionSummary, StatusReply,
};
use crate::transport::Channel;
use crate::transport::unix::{self, UnixChannel};
use std::io::{IsTerminal, Write as _};
use std::path::Path;

/// Run the parsed CLI command. Errors are rendered by `main` and always
/// exit non-zero; nothing in here panics or uses `todo!()`.
pub async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
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
        Command::Add(args) => cmd_add(args).await,
        Command::Rm(args) => cmd_rm(args).await,
        Command::Vault(args) => match args.action {
            VaultAction::Init => cmd_vault_init().await,
        },
        Command::Put(args) => cmd_put(args).await,
        Command::Get(args) => cmd_get(args).await,
        Command::Log(args) => cmd_log(args).await,
    }
}

async fn cmd_status(args: StatusArgs) -> anyhow::Result<()> {
    let socket_path = unix::resolve_socket_path();
    let mut chan = client::connect_or_spawn(&socket_path).await?;
    let reply = request_status(&mut chan).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&reply)?);
    } else {
        print_status_human(&reply, &socket_path);
    }
    Ok(())
}

async fn cmd_daemon(action: DaemonAction) -> anyhow::Result<()> {
    let socket_path = unix::resolve_socket_path();
    match action {
        DaemonAction::Run => crate::daemon::run(socket_path).await,
        DaemonAction::Start => cmd_daemon_start(&socket_path).await,
        DaemonAction::Stop => cmd_daemon_stop(&socket_path).await,
        DaemonAction::Status => cmd_daemon_status(&socket_path).await,
    }
}

async fn cmd_daemon_start(socket_path: &Path) -> anyhow::Result<()> {
    if UnixChannel::connect(socket_path).await.is_ok() {
        println!(
            "sloosh daemon is already running (socket at {})",
            socket_path.display()
        );
        return Ok(());
    }
    client::spawn_daemon_detached(socket_path)?;
    client::wait_for_daemon(socket_path).await?;
    println!(
        "sloosh daemon started (socket at {})",
        socket_path.display()
    );
    Ok(())
}

async fn cmd_daemon_stop(socket_path: &Path) -> anyhow::Result<()> {
    let Ok(mut chan) = UnixChannel::connect(socket_path).await else {
        println!(
            "sloosh daemon is not running (no socket at {})",
            socket_path.display()
        );
        return Ok(());
    };
    chan.send(&Request::Shutdown).await?;
    // Best-effort: read the Ok ack, but a closed connection is also a valid
    // sign the daemon shut down before flushing its reply.
    let _: Option<Response> = chan.recv().await.unwrap_or(None);
    println!("sloosh daemon stopped");
    Ok(())
}

async fn cmd_daemon_status(socket_path: &Path) -> anyhow::Result<()> {
    let Ok(mut chan) = UnixChannel::connect(socket_path).await else {
        println!(
            "sloosh daemon is not running (no socket at {})",
            socket_path.display()
        );
        return Ok(());
    };
    let reply = request_status(&mut chan).await?;
    print_status_human(&reply, socket_path);
    Ok(())
}

async fn request_status(chan: &mut UnixChannel) -> anyhow::Result<StatusReply> {
    chan.send(&Request::Status).await?;
    match chan.recv().await? {
        Some(Response::Status(reply)) => Ok(reply),
        Some(Response::Error { message }) => anyhow::bail!("daemon reported an error: {message}"),
        Some(other) => anyhow::bail!("daemon sent an unexpected reply: {other:?}"),
        None => anyhow::bail!(
            "daemon closed the connection without responding to Status; \
             check ~/.sloosh/daemon.log for a crash"
        ),
    }
}

fn print_status_human(reply: &proto::StatusReply, socket_path: &Path) {
    println!("sloosh daemon: running (pid {})", reply.pid);
    println!("  version:  {}", reply.version);
    println!("  uptime:   {}s", reply.uptime_secs);
    println!("  socket:   {}", socket_path.display());
    println!("  sessions: {}", reply.sessions.len());
    for s in &reply.sessions {
        println!("    - {} @ {} [{}]", s.name, s.host, s.state);
    }
    println!("  leases:   {}", reply.leases.len());
    for l in &reply.leases {
        println!(
            "    - {} — {} (pid {}), idle timeout in {}s",
            l.hosts.join(", "),
            l.anchor_name.as_deref().unwrap_or("unknown process"),
            l.anchor_pid,
            l.idle_remaining_secs,
        );
    }
}

/// `SLOOSH_LEASE` escape-hatch token from the environment, if this process
/// has one set (DESIGN.md §4) — forwarded on every host-touching request so
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

async fn cmd_run(args: RunArgs) -> anyhow::Result<()> {
    let req = Request::Run {
        host: args.host,
        command: args.command,
        session: args.session,
        timeout_secs: args.timeout,
        raw: args.raw,
        lease_token: lease_token_from_env(),
    };
    let resp = bail_on_error_or_unexpected(send_request(&req).await?)?;
    let Response::Run(reply) = resp else {
        anyhow::bail!("daemon sent an unexpected reply to Run: {resp:?}");
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&reply)?);
    } else {
        print_run_human(&reply);
    }
    Ok(())
}

fn print_run_human(reply: &RunReply) {
    println!("{} @ {} [{}]", reply.host, reply.session, reply.state);
    if let Some(code) = reply.exit_code {
        println!("exit code: {code}");
    }
    if let Some(reason) = &reply.dead_reason {
        println!("dead reason: {reason}");
    }
    if !reply.spool_path.is_empty() {
        println!("spool: {}", reply.spool_path);
    }
    println!("{}", reply.output);
    if reply.truncated {
        println!(
            "[output truncated in this reply; {} total bytes — see spool file for the rest]",
            reply.total_bytes
        );
    }
}

async fn cmd_peek(args: PeekArgs) -> anyhow::Result<()> {
    let req = Request::Peek {
        host: args.host,
        session: args.session,
        tail: args.tail,
        raw: args.raw,
        lease_token: lease_token_from_env(),
    };
    let resp = bail_on_error_or_unexpected(send_request(&req).await?)?;
    let Response::Peek(reply) = resp else {
        anyhow::bail!("daemon sent an unexpected reply to Peek: {resp:?}");
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&reply)?);
    } else {
        print_peek_human(&reply);
    }
    Ok(())
}

fn print_peek_human(reply: &PeekReply) {
    println!("{} @ {} [{}]", reply.host, reply.session, reply.state);
    if let Some(reason) = &reply.dead_reason {
        println!("dead reason: {reason}");
    }
    println!("{}", reply.output);
    if reply.truncated {
        println!(
            "[output truncated in this reply; {} total bytes]",
            reply.total_bytes
        );
    }
}

async fn cmd_send(args: SendArgs) -> anyhow::Result<()> {
    let req = Request::Send {
        host: args.host,
        keys: args.keys,
        session: args.session,
        newline: args.newline,
        lease_token: lease_token_from_env(),
    };
    bail_on_error_or_unexpected(send_request(&req).await?)?;
    println!("sent");
    Ok(())
}

async fn cmd_interrupt(args: InterruptArgs) -> anyhow::Result<()> {
    let req = Request::Interrupt {
        host: args.host,
        session: args.session,
        lease_token: lease_token_from_env(),
    };
    bail_on_error_or_unexpected(send_request(&req).await?)?;
    println!("interrupted");
    Ok(())
}

async fn cmd_open(args: OpenArgs) -> anyhow::Result<()> {
    let req = Request::Open {
        host: args.host,
        name: args.name,
        lease_token: lease_token_from_env(),
    };
    let resp = bail_on_error_or_unexpected(send_request(&req).await?)?;
    let Response::Session(summary) = resp else {
        anyhow::bail!("daemon sent an unexpected reply to Open: {resp:?}");
    };
    print_session_summary_human(&summary);
    Ok(())
}

async fn cmd_kill(args: KillArgs) -> anyhow::Result<()> {
    let req = Request::Kill {
        host: args.host,
        session: args.session,
        lease_token: lease_token_from_env(),
    };
    bail_on_error_or_unexpected(send_request(&req).await?)?;
    println!("killed");
    Ok(())
}

async fn cmd_ls(args: LsArgs) -> anyhow::Result<()> {
    let req = Request::Ls { host: args.host };
    let resp = bail_on_error_or_unexpected(send_request(&req).await?)?;
    let Response::Ls { sessions } = resp else {
        anyhow::bail!("daemon sent an unexpected reply to Ls: {resp:?}");
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&sessions)?);
    } else if sessions.is_empty() {
        println!("no sessions");
    } else {
        for s in &sessions {
            print_session_summary_human(s);
        }
    }
    Ok(())
}

fn print_session_summary_human(s: &SessionSummary) {
    let mut line = format!(
        "{} @ {} [{}] idle {}s",
        s.name, s.host, s.state, s.idle_secs
    );
    if let Some(reason) = &s.dead_reason {
        line.push_str(&format!(" ({reason})"));
    }
    println!("{line}");
}

// ---------------------------------------------------------------------
// Vault + lease authorization flow (DESIGN.md §4).
// ---------------------------------------------------------------------

/// Refuse to run a human-only command outside a real terminal (DESIGN.md
/// §2, §4): credential enrollment and lease approval are never meant to be
/// driven by an agent, so a non-interactive caller gets a self-teaching
/// error instead of a hung prompt or (worse) an ignored secret.
fn require_tty(command: &str) -> anyhow::Result<()> {
    if std::io::stdin().is_terminal() {
        Ok(())
    } else {
        anyhow::bail!(
            "`sloosh {command}` is a human-only command and refuses to run without a real \
             terminal attached to stdin (DESIGN.md §4). If you are a coding agent: do not try to \
             work around this — ask your user to run `sloosh {command}` themselves, in their own \
             terminal."
        )
    }
}

async fn cmd_request(args: RequestArgs) -> anyhow::Result<()> {
    let req = Request::RequestLease {
        hosts: args.hosts.clone(),
    };
    let resp = bail_on_error_or_unexpected(send_request(&req).await?)?;
    match resp {
        Response::Ok => {
            println!(
                "already authorized: an active lease already covers {}",
                args.hosts.join(", ")
            );
        }
        Response::LeaseRequestPending(info) => print_pending_request_instructions(&info),
        other => anyhow::bail!("daemon sent an unexpected reply to RequestLease: {other:?}"),
    }
    Ok(())
}

fn print_pending_request_instructions(info: &LeaseRequestSummary) {
    let anchor = info.anchor_name.as_deref().unwrap_or("an unknown process");
    println!(
        "Approval needed. Ask your user to run this in ANOTHER terminal:\n\n    sloosh approve {}\n\nGrants: {} — requested by {} (pid {}). Then wait; do not poll.",
        info.id,
        info.hosts.join(", "),
        anchor,
        info.anchor_pid,
    );
    if !info.vault_exists {
        println!(
            "\nNote: no credential vault exists yet, so the approve will be refused until your \
             user first runs `sloosh vault init` (also in their own terminal) to set a master \
             password."
        );
    }
}

async fn cmd_approve(args: ApproveArgs) -> anyhow::Result<()> {
    require_tty("approve")?;

    let describe_req = Request::DescribeLeaseRequest {
        id: args.request_id.clone(),
    };
    let resp = bail_on_error_or_unexpected(send_request(&describe_req).await?)?;
    let Response::LeaseRequestPending(info) = resp else {
        anyhow::bail!("daemon sent an unexpected reply to DescribeLeaseRequest: {resp:?}");
    };

    println!("Lease request {}", info.id);
    println!("  hosts:        {}", info.hosts.join(", "));
    println!(
        "  requested by: {} (pid {})",
        info.anchor_name.as_deref().unwrap_or("unknown process"),
        info.anchor_pid
    );
    println!("  age:          {}s", info.age_secs);
    if !info.vault_exists {
        anyhow::bail!(
            "no credential vault exists yet, so this request can't be approved (approval \
             verifies your master password, and there isn't one set) — run `sloosh vault init` \
             first to create the vault, then re-run `sloosh approve {}`",
            info.id
        );
    }
    println!();

    let master_password = prompt_master_password(true)?;

    let approve_req = Request::ApproveLease {
        id: args.request_id,
        master_password,
    };
    let resp = bail_on_error_or_unexpected(send_request(&approve_req).await?)?;
    let Response::LeaseActivated(activated) = resp else {
        anyhow::bail!("daemon sent an unexpected reply to ApproveLease: {resp:?}");
    };

    // Host-key confirmation happens after the lease is activated, because
    // only then can the daemon resolve vault-only aliases (the vault is
    // unlocked by the approval itself). The daemon reports which resolved
    // endpoints have no recorded key yet; this process dials each one
    // directly (a read-only probe, no secrets involved) so the human can
    // confirm its fingerprint (DESIGN.md §4).
    for unverified in &activated.unverified_hosts {
        confirm_and_record_host_key(&unverified.host, &unverified.hostname, unverified.port)
            .await?;
    }

    print_lease_activated(&activated);
    Ok(())
}

async fn cmd_vault_init() -> anyhow::Result<()> {
    require_tty("vault init")?;

    let vault_exists_resp =
        bail_on_error_or_unexpected(send_request(&Request::VaultExists).await?)?;
    let Response::VaultExists { exists } = vault_exists_resp else {
        anyhow::bail!("daemon sent an unexpected reply to VaultExists: {vault_exists_resp:?}");
    };
    if exists {
        println!(
            "a credential vault already exists — nothing to do. Use `sloosh add`/`sloosh rm` to \
             manage its entries."
        );
        return Ok(());
    }

    println!("Creating the sloosh credential vault (~/.sloosh/vault).");
    let master_password = prompt_master_password(false)?;
    bail_on_error_or_unexpected(send_request(&Request::InitVault { master_password }).await?)?;
    println!(
        "vault created. You can now approve lease requests (`sloosh approve <ID>`) and add \
         credentials (`sloosh add <alias> --hostname <host>`)."
    );
    Ok(())
}

/// Prompt for the master password: a single prompt if a vault already
/// exists, or a "set + confirm twice" flow for first-time setup (DESIGN.md
/// §1 "首次使用时提示设置主密码, 确认两次").
fn prompt_master_password(vault_exists: bool) -> anyhow::Result<SecretString> {
    if vault_exists {
        let pw = rpassword::prompt_password("Master password: ")?;
        return Ok(SecretString::new(pw));
    }
    loop {
        let pw1 = rpassword::prompt_password("Set a new master password: ")?;
        if pw1.is_empty() {
            println!("master password cannot be empty; try again.");
            continue;
        }
        let pw2 = rpassword::prompt_password("Confirm master password: ")?;
        if pw1 == pw2 {
            return Ok(SecretString::new(pw1));
        }
        println!("passwords did not match; try again.");
    }
}

/// Dial `hostname:port` directly (not through the daemon — this is a plain
/// read-only network probe with no secrets involved), show the human the
/// host key's SHA256 fingerprint, and on confirmation record it in
/// `~/.sloosh/known_hosts` (DESIGN.md §4). The endpoint comes pre-resolved
/// from the daemon's `ApproveLease` reply, which applies the same precedence
/// a real connection will (vault entry — visible to the daemon now the
/// approval unlocked it — then `~/.ssh/config`, then the literal alias), so
/// vault-only aliases get their real address confirmed too.
async fn confirm_and_record_host_key(host: &str, hostname: &str, port: u16) -> anyhow::Result<()> {
    print!("Fetching host key for {host} ({hostname}:{port})... ");
    std::io::stdout().flush().ok();
    let key = match ssh::fetch_host_key(hostname, port).await {
        Ok(key) => key,
        Err(e) => {
            println!("failed.");
            println!(
                "warning: could not fetch a host key for '{host}' to record automatically \
                 ({e}); continuing without recording one — the connection will still refuse to \
                 trust an unrecorded key. Run `ssh {host}` by hand once if you need to accept it \
                 manually."
            );
            return Ok(());
        }
    };
    println!("done.");

    let fingerprint = key.fingerprint(russh::keys::HashAlg::Sha256);
    print!(
        "Host key fingerprint for {host} ({hostname}:{port}):\n    {fingerprint}\nTrust this key and remember it? [y/N] "
    );
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if answer.trim().eq_ignore_ascii_case("y") {
        ssh::record_sloosh_known_host(hostname, port, &key)?;
        println!("recorded in ~/.sloosh/known_hosts");
    } else {
        println!(
            "not recorded — connecting to '{host}' will refuse to trust its key until this is \
             resolved (record it here, or add it to ~/.ssh/known_hosts by hand)."
        );
    }
    Ok(())
}

fn print_lease_activated(info: &LeaseActivatedInfo) {
    println!(
        "approved: {} (pid {}) can now access {}",
        info.anchor_name.as_deref().unwrap_or("unknown process"),
        info.anchor_pid,
        info.hosts.join(", "),
    );
    println!(
        "\nEscape hatch, only if needed (e.g. the caller isn't a descendant of this approval's \
         anchor process): set SLOOSH_LEASE={} in that process's environment. This token is shown \
         only this once.",
        info.token
    );
}

async fn cmd_add(args: AddArgs) -> anyhow::Result<()> {
    require_tty("add")?;

    let ssh_password = rpassword::prompt_password(format!("SSH password for {}: ", args.alias))?;

    let vault_exists_resp =
        bail_on_error_or_unexpected(send_request(&Request::VaultExists).await?)?;
    let Response::VaultExists { exists } = vault_exists_resp else {
        anyhow::bail!("daemon sent an unexpected reply to VaultExists: {vault_exists_resp:?}");
    };
    if !exists {
        println!("No credential vault exists yet — this creates one.");
    }
    let master_password = prompt_master_password(exists)?;

    let req = Request::AddCred {
        alias: args.alias.clone(),
        hostname: args.hostname,
        port: args.port,
        user: args.user,
        ssh_password: SecretString::new(ssh_password),
        master_password,
        replace: false,
    };
    bail_on_error_or_unexpected(send_request(&req).await?)?;
    println!("added '{}' to the vault", args.alias);
    Ok(())
}

async fn cmd_rm(args: RmArgs) -> anyhow::Result<()> {
    require_tty("rm")?;

    let master_password = SecretString::new(rpassword::prompt_password("Master password: ")?);
    let req = Request::RmCred {
        alias: args.alias.clone(),
        master_password,
    };
    bail_on_error_or_unexpected(send_request(&req).await?)?;
    println!("removed '{}' from the vault", args.alias);
    Ok(())
}

// ---------------------------------------------------------------------
// put/get over SFTP (DESIGN.md §5-6).
// ---------------------------------------------------------------------

/// Resolve `path` to an absolute path against *this* process's current
/// directory. Required before sending a local path to the daemon: the
/// daemon reads/writes the local filesystem directly on the CLI's behalf
/// (file content never crosses the socket), but the daemon's own working
/// directory is not the caller's, so a relative path would resolve
/// somewhere else entirely on that side. Existence is not required here —
/// `get`'s local destination may not exist yet — this is pure path
/// arithmetic, not a filesystem check.
fn resolve_local_path(path: &str) -> anyhow::Result<String> {
    let p = Path::new(path);
    if p.is_absolute() {
        return Ok(path.to_string());
    }
    let cwd = std::env::current_dir().map_err(|e| {
        anyhow::anyhow!(
            "could not resolve local path '{path}' to an absolute path: could not determine \
             the current directory ({e})"
        )
    })?;
    Ok(cwd.join(p).to_string_lossy().into_owned())
}

async fn cmd_put(args: PutArgs) -> anyhow::Result<()> {
    let local_path = resolve_local_path(&args.local_path)?;
    let req = Request::Put {
        host: args.host,
        local_path,
        remote_path: args.remote_path,
        session: args.session,
        lease_token: lease_token_from_env(),
    };
    let resp = bail_on_error_or_unexpected(send_request(&req).await?)?;
    let Response::Transfer(reply) = resp else {
        anyhow::bail!("daemon sent an unexpected reply to Put: {resp:?}");
    };
    println!(
        "put: {} -> {}:{} ({} bytes)",
        reply.local_path, reply.host, reply.remote_path, reply.bytes_transferred
    );
    Ok(())
}

async fn cmd_get(args: GetArgs) -> anyhow::Result<()> {
    let local_path = resolve_local_path(&args.local_path)?;
    let req = Request::Get {
        host: args.host,
        remote_path: args.remote_path,
        local_path,
        session: args.session,
        force: args.force,
        lease_token: lease_token_from_env(),
    };
    let resp = bail_on_error_or_unexpected(send_request(&req).await?)?;
    let Response::Transfer(reply) = resp else {
        anyhow::bail!("daemon sent an unexpected reply to Get: {resp:?}");
    };
    println!(
        "get: {}:{} -> {} ({} bytes)",
        reply.host, reply.remote_path, reply.local_path, reply.bytes_transferred
    );
    Ok(())
}

// ---------------------------------------------------------------------
// `sloosh log` (DESIGN.md §4) — reads ~/.sloosh/audit.jsonl directly, no
// daemon round-trip needed: the CLI and daemon run as the same user.
// ---------------------------------------------------------------------

async fn cmd_log(args: LogArgs) -> anyhow::Result<()> {
    let path = audit::audit_log_path();
    let raw_lines = audit::read_raw_lines(&path)
        .map_err(|e| anyhow::anyhow!("could not read audit log at {}: {e}", path.display()))?;

    let mut parsed: Vec<(String, serde_json::Value)> = Vec::new();
    for line in raw_lines {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            parsed.push((line, v));
        }
        // Malformed lines are silently skipped here (audit::record's own
        // best-effort posture means a torn write is expected to be rare and
        // not worth failing `sloosh log` over).
    }

    let filtered: Vec<(String, serde_json::Value)> = parsed
        .into_iter()
        .filter(|(_, v)| {
            args.host
                .as_deref()
                .is_none_or(|h| v.get("host").and_then(|x| x.as_str()) == Some(h))
        })
        .collect();

    let start = filtered.len().saturating_sub(args.count);
    let tail = &filtered[start..];

    if tail.is_empty() {
        match &args.host {
            Some(h) => println!("no audit log entries for host '{h}'"),
            None => println!("no audit log entries yet (~/.sloosh/audit.jsonl)"),
        }
        return Ok(());
    }

    if args.json {
        for (raw, _) in tail {
            println!("{raw}");
        }
    } else {
        for (_, v) in tail {
            print_audit_event_human(v);
        }
    }
    Ok(())
}

fn print_audit_event_human(v: &serde_json::Value) {
    let ts = v.get("ts").and_then(|x| x.as_str()).unwrap_or("?");
    let event = v.get("event").and_then(|x| x.as_str()).unwrap_or("?");
    let mut fields = String::new();
    if let Some(obj) = v.as_object() {
        let mut keys: Vec<&String> = obj.keys().filter(|k| *k != "ts" && *k != "event").collect();
        keys.sort();
        for k in keys {
            fields.push_str(&format!(" {k}={}", render_field_value(&obj[k])));
        }
    }
    println!("{ts}  {event}{fields}");
}

fn render_field_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
