use super::args::{InterruptArgs, KillArgs, LsArgs, OpenArgs, PeekArgs, RunArgs, SendArgs};
use super::{bail_on_error_or_unexpected, lease_token_from_env, send_request};
use crate::proto::{PeekReply, Request, Response, RunReply, SessionSummary};

pub(super) async fn cmd_run(args: RunArgs) -> anyhow::Result<()> {
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

pub(super) async fn cmd_peek(args: PeekArgs) -> anyhow::Result<()> {
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

pub(super) async fn cmd_send(args: SendArgs) -> anyhow::Result<()> {
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

pub(super) async fn cmd_interrupt(args: InterruptArgs) -> anyhow::Result<()> {
    let req = Request::Interrupt {
        host: args.host,
        session: args.session,
        lease_token: lease_token_from_env(),
    };
    bail_on_error_or_unexpected(send_request(&req).await?)?;
    println!("interrupted");
    Ok(())
}

pub(super) async fn cmd_open(args: OpenArgs) -> anyhow::Result<()> {
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

pub(super) async fn cmd_kill(args: KillArgs) -> anyhow::Result<()> {
    let req = Request::Kill {
        host: args.host,
        session: args.session,
        lease_token: lease_token_from_env(),
    };
    bail_on_error_or_unexpected(send_request(&req).await?)?;
    println!("killed");
    Ok(())
}

pub(super) async fn cmd_ls(args: LsArgs) -> anyhow::Result<()> {
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
        for session in &sessions {
            print_session_summary_human(session);
        }
    }
    Ok(())
}

fn print_session_summary_human(session: &SessionSummary) {
    let mut line = format!(
        "{} @ {} [{}] idle {}s",
        session.name, session.host, session.state, session.idle_secs
    );
    if let Some(reason) = &session.dead_reason {
        line.push_str(&format!(" ({reason})"));
    }
    println!("{line}");
}
