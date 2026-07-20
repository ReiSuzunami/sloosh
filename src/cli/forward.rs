//! Port-forward command surface.

use clap::Parser as _;

use super::args::{ForwardAction, ForwardLsArgs, ForwardOpenArgs, ForwardStopArgs};
use super::{bail_on_error_or_unexpected, lease_token_from_env, send_request};
use crate::proto::{self, ForwardDirection, Request, Response};

pub(super) async fn cmd_forward(action: ForwardAction) -> anyhow::Result<()> {
    match action {
        ForwardAction::Ls(args) => cmd_forward_ls(args).await,
        ForwardAction::Stop(args) => cmd_forward_stop(args).await,
        ForwardAction::Open(raw_args) => cmd_forward_open(raw_args).await,
    }
}

async fn cmd_forward_open(raw_args: Vec<String>) -> anyhow::Result<()> {
    let ForwardOpenArgs {
        host,
        local,
        remote,
        json,
    } = ForwardOpenArgs::try_parse_from(&raw_args).unwrap_or_else(|error| error.exit());
    let direction = match (local, remote) {
        (Some(spec), None) => ForwardDirection::Local { spec },
        (None, Some(spec)) => ForwardDirection::Remote { spec },
        _ => unreachable!("ForwardOpenArgs's ArgGroup enforces exactly one of -L/-R"),
    };
    let request = Request::Forward {
        host,
        direction,
        lease_token: lease_token_from_env(),
    };
    let response = bail_on_error_or_unexpected(send_request(&request).await?)?;
    let Response::Forward(opened) = response else {
        anyhow::bail!("daemon sent an unexpected reply to Forward: {response:?}");
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&opened)?);
    } else {
        print_forward_opened_human(&opened);
    }
    Ok(())
}

fn print_forward_opened_human(opened: &proto::ForwardOpened) {
    println!(
        "{}  {} -{} {}  listening on {}",
        opened.id, opened.host, opened.direction, opened.spec, opened.listen_addr
    );
    println!(
        "(the daemon keeps this forward alive in the background; `sloosh forward stop {}` to end it)",
        opened.id
    );
}

async fn cmd_forward_ls(args: ForwardLsArgs) -> anyhow::Result<()> {
    let response = bail_on_error_or_unexpected(send_request(&Request::ForwardLs).await?)?;
    let Response::ForwardLs { forwards } = response else {
        anyhow::bail!("daemon sent an unexpected reply to ForwardLs: {response:?}");
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&forwards)?);
    } else if forwards.is_empty() {
        println!("no active forwards");
    } else {
        for forward in &forwards {
            print_forward_summary_human(forward);
        }
    }
    Ok(())
}

fn print_forward_summary_human(forward: &proto::ForwardSummary) {
    println!(
        "{}  {} -{} {}  {} open tunnel(s)  age {}s",
        forward.id,
        forward.host,
        forward.direction,
        forward.spec,
        forward.tunnel_count,
        forward.age_secs
    );
}

async fn cmd_forward_stop(args: ForwardStopArgs) -> anyhow::Result<()> {
    let request = Request::ForwardStop {
        id: args.id.clone(),
    };
    bail_on_error_or_unexpected(send_request(&request).await?)?;
    println!("stopped {}", args.id);
    Ok(())
}
