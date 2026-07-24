//! Human-only vault setup and lease approval flow.

use std::future::Future;
use std::io::{IsTerminal as _, Write as _};

use super::args::{ApproveArgs, RequestArgs};
use super::{bail_on_error_or_unexpected, send_request};
use crate::daemon::{ssh, vault};
use crate::proto::{LeaseActivatedInfo, LeaseRequestSummary, Request, Response, SecretString};

/// Refuse to run a human-only command outside a real terminal. Credential
/// enrollment and lease approval must never be driven by an agent.
pub(super) fn require_tty(command: &str) -> anyhow::Result<()> {
    if std::io::stdin().is_terminal() {
        Ok(())
    } else {
        anyhow::bail!(
            "`sloosh {command}` is a human-only command and refuses to run without a real \
             terminal attached to stdin (docs/internals/architecture.md). If you are a coding agent: do not try to \
             work around this — ask your user to run `sloosh {command}` themselves, in their own \
             terminal."
        )
    }
}

pub(super) async fn cmd_request(args: RequestArgs) -> anyhow::Result<()> {
    let req = Request::RequestLease {
        hosts: args.hosts.clone(),
    };
    let resp = bail_on_error_or_unexpected(send_request(&req).await?)?;
    match resp {
        Response::Ok => {
            println!(
                "authorized: an active lease covers {}",
                display_host_list(&args.hosts)
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
        display_host_list(&info.hosts),
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

pub(super) async fn cmd_approve(args: ApproveArgs) -> anyhow::Result<()> {
    require_tty("approve")?;

    let describe_req = Request::DescribeLeaseRequest {
        id: args.request_id.clone(),
    };
    let resp = bail_on_error_or_unexpected(send_request(&describe_req).await?)?;
    let Response::LeaseRequestPending(info) = resp else {
        anyhow::bail!("daemon sent an unexpected reply to DescribeLeaseRequest: {resp:?}");
    };

    println!("Lease request {}", info.id);
    println!("  hosts:        {}", display_host_list(&info.hosts));
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
    vault::unlock_for_lease(master_password.expose_secret().as_bytes())
        .await
        .map_err(|error| {
            anyhow::anyhow!("could not unlock vault to preview full host list: {error}")
        })?;

    // Keep this process-local cache alive through host-key confirmation: a
    // ProxyJump-aware probe can resolve vault-only bastions without another
    // password prompt. Clear it before every return path.
    let approval_result: anyhow::Result<LeaseActivatedInfo> = async {
        let activated = resolve_confirm_and_submit_approval(
            args.request_id,
            master_password,
            info.hosts,
            |hosts| async move { ssh::expand_lease_hosts(&hosts).await },
            confirm_approved_hosts,
            |request| async move { send_request(&request).await },
        )
        .await?;

        for target in ssh::host_key_confirmation_order(&activated.hosts).await {
            if ssh::host_has_known_key(&target.hostname, target.port) {
                continue;
            }
            confirm_and_record_host_key(&target).await?;
        }
        Ok(activated)
    }
    .await;
    vault::clear_cache().await;
    let activated = approval_result?;
    print_lease_activated(&activated);
    Ok(())
}

async fn resolve_confirm_and_submit_approval<Resolve, ResolveFuture, Confirm, Send, SendFuture>(
    request_id: String,
    master_password: SecretString,
    requested_hosts: Vec<String>,
    resolve_scope: Resolve,
    confirm_scope: Confirm,
    send: Send,
) -> anyhow::Result<LeaseActivatedInfo>
where
    Resolve: FnOnce(Vec<String>) -> ResolveFuture,
    ResolveFuture: Future<Output = Result<Vec<String>, ssh::SshError>>,
    Confirm: FnOnce(&[String]) -> anyhow::Result<()>,
    Send: FnOnce(Request) -> SendFuture,
    SendFuture: Future<Output = anyhow::Result<Response>>,
{
    let approved_hosts = resolve_scope(requested_hosts).await.map_err(|error| {
        anyhow::anyhow!("could not resolve full ProxyJump approval scope: {error}")
    })?;
    confirm_scope(&approved_hosts)?;

    let approve_req = Request::ApproveLease {
        id: request_id,
        master_password,
        approved_hosts,
    };
    let resp = bail_on_error_or_unexpected(send(approve_req).await?)?;
    let Response::LeaseActivated(activated) = resp else {
        anyhow::bail!("daemon sent an unexpected reply to ApproveLease: {resp:?}");
    };
    Ok(activated)
}

fn confirm_approved_hosts(hosts: &[String]) -> anyhow::Result<()> {
    println!("Full host grant after vault-backed ProxyJump expansion:");
    for host in hosts {
        println!("  - {host:?}");
    }
    print!("Approve exactly this host list? [y/N] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        anyhow::bail!("approval cancelled; lease request remains pending");
    }
    Ok(())
}

pub(super) fn display_host_list(hosts: &[String]) -> String {
    hosts
        .iter()
        .map(|host| format!("{host:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) async fn cmd_vault_init_inner() -> anyhow::Result<Option<SecretString>> {
    let vault_exists_resp =
        bail_on_error_or_unexpected(send_request(&Request::VaultExists).await?)?;
    let Response::VaultExists { exists } = vault_exists_resp else {
        anyhow::bail!("daemon sent an unexpected reply to VaultExists: {vault_exists_resp:?}");
    };
    if exists {
        println!(
            "a credential vault already exists — nothing to do. Use `sloosh host add/list/edit/rm` to \
             manage its entries."
        );
        return Ok(None);
    }

    println!("Creating the sloosh credential vault (~/.sloosh/vault).");
    let master_password = prompt_master_password(false)?;
    bail_on_error_or_unexpected(
        send_request(&Request::InitVault {
            master_password: master_password.clone(),
        })
        .await?,
    )?;
    println!(
        "vault created. You can now approve lease requests (`sloosh approve <ID>`) and add \
         credentials (`sloosh host add <alias> --hostname <host>`)."
    );
    Ok(Some(master_password))
}

/// Prompt once for an existing vault, or set and confirm for first setup.
pub(super) fn prompt_master_password(vault_exists: bool) -> anyhow::Result<SecretString> {
    if vault_exists {
        let password = rpassword::prompt_password("Master password: ")?;
        return Ok(SecretString::new(password));
    }
    loop {
        let password = rpassword::prompt_password("Set a new master password: ")?;
        if password.is_empty() {
            println!("master password cannot be empty; try again.");
            continue;
        }
        let confirmation = rpassword::prompt_password("Confirm master password: ")?;
        if password == confirmation {
            return Ok(SecretString::new(password));
        }
        println!("passwords did not match; try again.");
    }
}

async fn confirm_and_record_host_key(
    target: &ssh::HostKeyConfirmationTarget,
) -> anyhow::Result<()> {
    let host = &target.alias;
    let host_display = format!("{host:?}");
    print!("Fetching host key for {host_display} through configured SSH route... ");
    std::io::stdout().flush().ok();
    let probe = match ssh::fetch_host_key_for_confirmation_target(target).await {
        Ok(probe) => probe,
        Err(error) => {
            println!("failed.");
            println!(
                "warning: could not fetch a host key for {host_display} to record automatically \
                 ({error}); continuing without recording one — the connection will still refuse to \
                 trust an unrecorded key. Verify its ProxyJump route and record the endpoint key \
                 manually, or re-run this approval after fixing the route."
            );
            return Ok(());
        }
    };
    println!("done.");

    let fingerprint = probe.key.fingerprint(russh::keys::HashAlg::Sha256);
    let endpoint_display = format!("{:?}:{}", probe.hostname, probe.port);
    print!(
        "Host key fingerprint for {host_display} ({endpoint_display}):\n    {fingerprint}\nTrust this key and remember it? [y/N] "
    );
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if answer.trim().eq_ignore_ascii_case("y") {
        ssh::record_sloosh_known_host(&probe.hostname, probe.port, &probe.key)?;
        println!("recorded in ~/.sloosh/known_hosts");
    } else {
        println!(
            "not recorded — connecting to {host_display} will refuse to trust its key until this is \
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
        display_host_list(&info.hosts),
    );
    println!(
        "\nEscape hatch, only if needed (e.g. the caller isn't a descendant of this approval's \
         anchor process): set SLOOSH_LEASE={} in that process's environment. This token is shown \
         only this once.",
        info.token
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn route_expansion_failure_never_sends_approve_lease() {
        let confirmations = Arc::new(AtomicUsize::new(0));
        let sends = Arc::new(AtomicUsize::new(0));
        let observed_confirmations = confirmations.clone();
        let observed_sends = sends.clone();

        let error = resolve_confirm_and_submit_approval(
            "request-id".to_string(),
            SecretString::new("test-master-password"),
            vec!["target".to_string()],
            |_| async { Err(ssh::SshError::ProxyJumpTooDeep { limit: 8 }) },
            move |_| {
                observed_confirmations.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
            move |_| {
                observed_sends.fetch_add(1, Ordering::Relaxed);
                async { Ok(Response::Ok) }
            },
        )
        .await
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("could not resolve full ProxyJump approval scope"),
            "{error}"
        );
        assert_eq!(confirmations.load(Ordering::Relaxed), 0);
        assert_eq!(sends.load(Ordering::Relaxed), 0);
    }
}
