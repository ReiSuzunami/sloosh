//! Vault-backed host inventory and credential enrollment commands.

use super::args::{
    AddArgs, HostAuthArg, HostEditArgs, HostListArgs, HostShowArgs, HostTrustArgs, RmArgs,
};
use super::{bail_on_error_or_unexpected, prompt_master_password, require_tty, send_request};
use crate::human_host_key::{
    self, HostKeyTrustAction, HostKeyTrustError, HostKeyTrustPreview, HostKeyTrustSource,
    HostKeyTrustState,
};
use crate::proto::{self, HostAuth, HostRoute, HostSummary, Request, Response, SecretString};

pub(super) async fn cmd_add(args: AddArgs) -> anyhow::Result<()> {
    require_tty("add")?;
    let auth = host_auth_input(args.auth, args.key_file, &args.alias)?;
    let route = host_route_input(args.via, args.proxy_jump, args.jump);

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
        auth,
        master_password,
        replace: false,
        route,
    };
    bail_on_error_or_unexpected(send_request(&req).await?)?;
    println!("added '{}' to the vault", args.alias);
    Ok(())
}

pub(super) async fn cmd_rm(args: RmArgs) -> anyhow::Result<()> {
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

async fn read_host_inventory(master_password: SecretString) -> anyhow::Result<Vec<HostSummary>> {
    let response =
        bail_on_error_or_unexpected(send_request(&Request::ListHosts { master_password }).await?)?;
    let Response::Hosts { hosts } = response else {
        anyhow::bail!("daemon sent an unexpected reply to ListHosts: {response:?}");
    };
    Ok(hosts)
}

pub(super) async fn cmd_host_list(args: HostListArgs) -> anyhow::Result<()> {
    require_tty("host list")?;
    let master_password = SecretString::new(rpassword::prompt_password("Master password: ")?);
    let hosts = read_host_inventory(master_password).await?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&hosts)?);
        return Ok(());
    }
    if hosts.is_empty() {
        println!("No vault-backed hosts configured.");
        return Ok(());
    }

    println!("ALIAS\tENDPOINT\tUSER\tAUTH\tROUTE");
    for host in hosts {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            escape_terminal_controls(&host.alias),
            display_host_endpoint(&host),
            escape_terminal_controls(host.user.as_deref().unwrap_or("(default)")),
            host_auth_label(host.auth),
            escape_terminal_controls(&host_route_label(&host.route))
        );
    }
    Ok(())
}

pub(super) async fn cmd_host_show(args: HostShowArgs) -> anyhow::Result<()> {
    require_tty("host show")?;
    let master_password = SecretString::new(rpassword::prompt_password("Master password: ")?);
    let hosts = read_host_inventory(master_password).await?;
    let host = hosts
        .into_iter()
        .find(|host| host.alias == args.alias)
        .ok_or_else(|| anyhow::anyhow!("no host named '{}' in the vault", args.alias))?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&host)?);
    } else {
        println!("Alias:    {}", escape_terminal_controls(&host.alias));
        println!("Hostname: {}", escape_terminal_controls(&host.hostname));
        println!("Port:     {}", host.port.unwrap_or(22));
        println!(
            "User:     {}",
            escape_terminal_controls(host.user.as_deref().unwrap_or("(default)"))
        );
        println!("Auth:     {}", host_auth_label(host.auth));
        println!(
            "Route:    {}",
            escape_terminal_controls(&host_route_label(&host.route))
        );
    }
    Ok(())
}

fn print_host_key_preview(preview: &HostKeyTrustPreview) {
    println!();
    println!(
        "{}",
        match preview.state {
            HostKeyTrustState::New => "REMOTE HOST KEY IS NOT TRUSTED",
            HostKeyTrustState::Changed | HostKeyTrustState::ExternalMismatch =>
                "WARNING: REMOTE HOST KEY HAS CHANGED",
        }
    );
    println!(
        "Host:        {} ({})",
        escape_terminal_controls(&preview.host),
        escape_terminal_controls(&preview.requested_host)
    );
    println!(
        "Endpoint:    {}:{}",
        escape_terminal_controls(&preview.hostname),
        preview.port
    );
    println!(
        "Algorithm:   {}",
        escape_terminal_controls(&preview.algorithm)
    );
    if let Some(stored) = preview.stored_fingerprint.as_deref() {
        println!("Stored key:  {}", escape_terminal_controls(stored));
    }
    println!(
        "New key:     {}",
        escape_terminal_controls(&preview.fingerprint)
    );
    if let Some(source) = preview.source {
        println!(
            "Stored in:   {}",
            match source {
                HostKeyTrustSource::Sloosh => "~/.sloosh/known_hosts",
                HostKeyTrustSource::OpenSsh => "~/.ssh/known_hosts",
            }
        );
    }
    println!(
        "Verify the new fingerprint through a trusted, independent channel before continuing."
    );
}

fn prompt_host_key_action(
    preview: &HostKeyTrustPreview,
) -> anyhow::Result<Option<HostKeyTrustAction>> {
    let prompt = match preview.state {
        HostKeyTrustState::New => "[a]dd, [r]echeck, or [c]ancel? ",
        HostKeyTrustState::Changed if preview.replaceable => "[p]replace, [r]echeck, or [c]ancel? ",
        HostKeyTrustState::Changed | HostKeyTrustState::ExternalMismatch => {
            "[r]echeck or [c]ancel? "
        }
    };
    loop {
        eprint!("{prompt}");
        use std::io::Write as _;
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        match answer.trim().to_ascii_lowercase().as_str() {
            "a" | "add" if preview.state == HostKeyTrustState::New => {
                return Ok(Some(HostKeyTrustAction::Add));
            }
            "p" | "replace"
                if preview.state == HostKeyTrustState::Changed && preview.replaceable =>
            {
                return Ok(Some(HostKeyTrustAction::Replace));
            }
            "r" | "recheck" => return Ok(None),
            "c" | "cancel" | "" => anyhow::bail!("host-key trust cancelled"),
            _ => eprintln!("Choose one of the actions shown."),
        }
    }
}

pub(super) async fn cmd_host_trust(args: HostTrustArgs) -> anyhow::Result<()> {
    require_tty("host trust")?;
    let master_password = SecretString::new(rpassword::prompt_password("Master password: ")?);
    loop {
        let Some(preview) = human_host_key::preview_host_key(&args.alias, &master_password).await?
        else {
            println!("all host keys for '{}' are trusted", args.alias);
            return Ok(());
        };
        print_host_key_preview(&preview);
        if matches!(preview.state, HostKeyTrustState::ExternalMismatch) {
            eprintln!(
                "Sloosh will not modify ~/.ssh/known_hosts; resolve that entry manually, then recheck."
            );
        } else if !preview.replaceable {
            eprintln!(
                "This entry is not a single Sloosh-managed host line; update it manually, then recheck."
            );
        }
        let Some(action) = prompt_host_key_action(&preview)? else {
            continue;
        };
        match human_host_key::apply_host_key_action(&preview, action, &master_password).await {
            Ok(()) => {}
            Err(HostKeyTrustError::PreviewChanged | HostKeyTrustError::AlreadyTrusted) => {
                eprintln!("Host-key state changed; refreshing before any write.");
            }
            Err(error) => return Err(error.into()),
        }
    }
}

pub(super) async fn cmd_host_edit(args: HostEditArgs) -> anyhow::Result<()> {
    require_tty("host edit")?;
    if args.hostname.is_none()
        && args.user.is_none()
        && !args.clear_user
        && args.port.is_none()
        && !args.clear_port
        && args.auth.is_none()
        && args.key_file.is_none()
        && args.via.is_none()
        && args.proxy_jump.is_none()
        && !args.direct
        && args.jump.is_none()
        && !args.clear_jump
        && !args.change_password
    {
        anyhow::bail!("no changes requested; pass a field option or --change-password");
    }

    let master_password = SecretString::new(rpassword::prompt_password("Master password: ")?);
    let hosts = read_host_inventory(master_password.clone()).await?;
    let current = hosts
        .into_iter()
        .find(|host| host.alias == args.alias)
        .ok_or_else(|| anyhow::anyhow!("no host named '{}' in the vault", args.alias))?;
    if args.key_file.is_some() && args.auth != Some(HostAuthArg::KeyFile) {
        anyhow::bail!("--key-file requires --auth key-file");
    }
    let auth = if args.change_password {
        Some(host_auth_input(HostAuthArg::Password, None, &args.alias)?)
    } else {
        args.auth
            .map(|auth| host_auth_input(auth, args.key_file, &args.alias))
            .transpose()?
    };
    let route = if args.direct || args.clear_jump {
        HostRoute::Direct
    } else if args.via.is_some() || args.proxy_jump.is_some() || args.jump.is_some() {
        host_route_input(args.via, args.proxy_jump, args.jump)
    } else {
        current.route
    };
    let request = Request::UpdateHost {
        alias: args.alias.clone(),
        hostname: args.hostname.unwrap_or(current.hostname),
        port: if args.clear_port {
            None
        } else {
            args.port.or(current.port)
        },
        user: if args.clear_user {
            None
        } else {
            args.user.or(current.user)
        },
        route,
        auth,
        master_password,
    };
    bail_on_error_or_unexpected(send_request(&request).await?)?;
    println!("updated '{}' in the vault", args.alias);
    Ok(())
}

fn host_auth_input(
    auth: HostAuthArg,
    key_file: Option<String>,
    alias: &str,
) -> anyhow::Result<HostAuth> {
    Ok(match auth {
        HostAuthArg::Agent => {
            if key_file.is_some() {
                anyhow::bail!("--key-file can only be used with --auth key-file");
            }
            HostAuth::Agent
        }
        HostAuthArg::Password => {
            if key_file.is_some() {
                anyhow::bail!("--key-file can only be used with --auth key-file");
            }
            HostAuth::Password {
                password: SecretString::new(rpassword::prompt_password(format!(
                    "SSH password for {alias}: "
                ))?),
            }
        }
        HostAuthArg::KeyFile => HostAuth::KeyFile {
            path: key_file
                .ok_or_else(|| anyhow::anyhow!("--auth key-file requires --key-file <PATH>"))?,
        },
    })
}

fn host_route_input(
    via: Option<String>,
    proxy_jump: Option<String>,
    legacy_jump: Option<String>,
) -> HostRoute {
    if let Some(alias) = via {
        HostRoute::ManagedHost { alias }
    } else if let Some(spec) = proxy_jump.or(legacy_jump) {
        HostRoute::ProxyJump { spec }
    } else {
        HostRoute::Direct
    }
}

fn host_auth_label(auth: proto::HostAuthKind) -> &'static str {
    match auth {
        proto::HostAuthKind::Agent => "agent",
        proto::HostAuthKind::Password => "password",
        proto::HostAuthKind::KeyFile => "key-file",
    }
}

fn host_route_label(route: &HostRoute) -> String {
    match route {
        HostRoute::Direct => "Direct".to_string(),
        HostRoute::ManagedHost { alias } => format!("Via {alias}"),
        HostRoute::ProxyJump { spec } => format!("ProxyJump {spec}"),
    }
}

pub(super) fn display_host_endpoint(host: &HostSummary) -> String {
    let hostname = escape_terminal_controls(&host.hostname);
    match host.port {
        Some(port) if host.hostname.contains(':') => format!("[{hostname}]:{port}"),
        Some(port) => format!("{hostname}:{port}"),
        None => hostname,
    }
}

pub(super) fn escape_terminal_controls(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    escaped
}
