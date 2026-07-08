//! CLI: clap command definitions, client-side dispatch, daemon auto-spawn
//! (DESIGN.md §6, §8).

mod args;
mod client;

pub use args::Cli;
use args::{
    Command, DaemonAction, InterruptArgs, KillArgs, LsArgs, OpenArgs, PeekArgs, RunArgs, SendArgs,
    StatusArgs,
};

use crate::proto::{self, PeekReply, Request, Response, RunReply, SessionSummary, StatusReply};
use crate::transport::Channel;
use crate::transport::unix::{self, UnixChannel};
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
        Command::Request(_) => not_implemented("request"),
        Command::Approve(_) => not_implemented("approve"),
        Command::Add(_) => not_implemented("add"),
        Command::Rm(_) => not_implemented("rm"),
        Command::Put(_) => not_implemented("put"),
        Command::Get(_) => not_implemented("get"),
        Command::Log(_) => not_implemented("log"),
    }
}

fn not_implemented(name: &str) -> anyhow::Result<()> {
    anyhow::bail!(
        "`sloosh {name}` is not implemented yet. Milestone 1 only wires up `status` and `daemon`; \
         see DESIGN.md §6 for the full phase-1 command surface as it lands."
    )
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
        println!("    - {} (expires in {}s)", l.host, l.expires_in_secs);
    }
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
    };
    bail_on_error_or_unexpected(send_request(&req).await?)?;
    println!("sent");
    Ok(())
}

async fn cmd_interrupt(args: InterruptArgs) -> anyhow::Result<()> {
    let req = Request::Interrupt {
        host: args.host,
        session: args.session,
    };
    bail_on_error_or_unexpected(send_request(&req).await?)?;
    println!("interrupted");
    Ok(())
}

async fn cmd_open(args: OpenArgs) -> anyhow::Result<()> {
    let req = Request::Open {
        host: args.host,
        name: args.name,
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
