//! System host inventory and narrowly scoped edits to the user's OpenSSH config.
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::daemon::ssh::config::{SshConfig, split_directive};
use crate::proto::{HostAuthKind, HostRoute, HostSummary};
use anyhow::{Context, ensure};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

fn path() -> anyhow::Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".ssh/config"))
}

pub struct SystemHost {
    pub host: HostSummary,
    pub edit_error: Option<String>,
}

pub fn list() -> anyhow::Result<Vec<SystemHost>> {
    let path = path()?;
    let text = read_config(&path)?;
    let config = SshConfig::parse_at(&text, &path);
    Ok(config
        .aliases()
        .into_iter()
        .map(|alias| {
            let host = config.resolve(&alias);
            let edit_error = rewrite(&text, &path, &alias, None, true)
                .err()
                .map(|error| error.to_string());
            SystemHost {
                edit_error,
                host: HostSummary {
                    alias,
                    hostname: host.hostname,
                    port: Some(host.port),
                    user: Some(host.user),
                    auth: HostAuthKind::Agent,
                    route: host
                        .proxy_jump
                        .map_or(HostRoute::Direct, |spec| HostRoute::ProxyJump { spec }),
                },
            }
        })
        .collect())
}

pub fn save(host: &HostSummary, replace: bool) -> anyhow::Result<()> {
    edit_at(&path()?, &host.alias, Some(host), replace)
}

pub fn remove(alias: &str) -> anyhow::Result<()> {
    edit_at(&path()?, alias, None, true)
}

fn read_config(path: &Path) -> anyhow::Result<String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o022 == 0,
        "SSH config must be a user-owned file, not writable by other users"
    );
    let mut text = String::new();
    file.take(MAX_CONFIG_BYTES + 1).read_to_string(&mut text)?;
    ensure!(
        text.len() as u64 <= MAX_CONFIG_BYTES,
        "SSH config exceeds 1 MiB"
    );
    Ok(text)
}

fn safe_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._:@,[]".contains(&byte))
}

fn rewrite(
    text: &str,
    path: &Path,
    alias: &str,
    host: Option<&HostSummary>,
    replace: bool,
) -> anyhow::Result<String> {
    ensure!(
        safe_value(alias) && !alias.contains(['@', ',', '[', ']', ':']),
        "Use a literal SSH Host alias"
    );
    let lines = text.split_inclusive('\n').collect::<Vec<_>>();
    let boundaries = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            let (key, rest) = split_directive(line)?;
            (key.eq_ignore_ascii_case("host") || key.eq_ignore_ascii_case("match"))
                .then_some((index, key, rest))
        })
        .collect::<Vec<_>>();
    let matches = boundaries
        .iter()
        .enumerate()
        .filter(|(_, (_, key, rest))| {
            key.eq_ignore_ascii_case("host") && rest.split_whitespace().any(|name| name == alias)
        })
        .collect::<Vec<_>>();
    let range = if replace {
        ensure!(
            matches.len() == 1,
            "Edit this host in its source SSH config: no unique root-file Host block"
        );
        let (position, (start, _, names)) = matches[0];
        ensure!(
            names.trim() == alias,
            "Edit shared or commented Host headers directly in SSH config"
        );
        Some(
            *start
                ..boundaries
                    .get(position + 1)
                    .map_or(lines.len(), |(index, _, _)| *index),
        )
    } else {
        ensure!(
            !SshConfig::parse_at(text, path).contains_alias(alias),
            "Host already exists in SSH config; edit it instead"
        );
        None
    };
    let mut block = String::new();
    if host.is_none() {
        if let Some(range) = &range {
            ensure!(
                !lines[range.clone()].iter().any(|line| split_directive(line)
                    .is_some_and(|(key, _)| key.eq_ignore_ascii_case("include"))),
                "This Host block includes other files; remove it in the source config directly"
            );
        }
    }
    if let Some(host) = host {
        ensure!(safe_value(&host.hostname), "Invalid SSH hostname");
        ensure!(host.port != Some(0), "SSH port must be between 1 and 65535");
        if let Some(user) = &host.user {
            ensure!(safe_value(user), "Invalid SSH user");
        }
        let jump = match &host.route {
            HostRoute::Direct => "none",
            HostRoute::ManagedHost { alias } => alias,
            HostRoute::ProxyJump { spec } => spec,
        };
        ensure!(safe_value(jump), "Invalid ProxyJump value");
        block = format!(
            "Host {alias}\n    HostName {}\n    Port {}\n",
            host.hostname,
            host.port.unwrap_or(22)
        );
        if let Some(user) = &host.user {
            block.push_str(&format!("    User {user}\n"));
        }
        block.push_str(&format!("    ProxyJump {jump}\n"));
        if let Some(range) = &range {
            // Keep comments, identity settings, includes, and all other directives.
            for line in &lines[range.start + 1..range.end] {
                let replaced = split_directive(line).is_some_and(|(key, _)| {
                    ["hostname", "port", "user", "proxyjump"]
                        .iter()
                        .any(|name| key.eq_ignore_ascii_case(name))
                });
                if !replaced {
                    block.push_str(line);
                }
            }
        }
    }
    let updated = match range {
        Some(range) => format!(
            "{}{}{}",
            lines[..range.start].concat(),
            block,
            lines[range.end..].concat()
        ),
        // Explicit new hosts precede defaults and Include directives.
        None => {
            let prefix_end = boundaries
                .first()
                .map_or(lines.len(), |(index, _, _)| *index);
            let has_globals = lines[..prefix_end]
                .iter()
                .any(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'));
            format!(
                "{block}\n{}{text}",
                if has_globals { "Host *\n" } else { "" }
            )
        }
    };
    if let Some(host) = host {
        let resolved = SshConfig::parse_at(&updated, path).resolve_for_connection(alias)?;
        let desired_jump = match &host.route {
            HostRoute::Direct => None,
            HostRoute::ManagedHost { alias } => Some(alias.as_str()),
            HostRoute::ProxyJump { spec } => Some(spec.as_str()),
        };
        ensure!(
            resolved.hostname == host.hostname
                && resolved.port == host.port.unwrap_or(22)
                && host.user.as_ref().is_none_or(|user| &resolved.user == user)
                && resolved.proxy_jump.as_deref() == desired_jump,
            "Earlier SSH config settings override this host; edit the source config directly"
        );
    }
    Ok(updated)
}

fn edit_at(
    path: &Path,
    alias: &str,
    host: Option<&HostSummary>,
    replace: bool,
) -> anyhow::Result<()> {
    let parent = path.parent().context("SSH config has no parent")?;
    crate::transport::unix::ensure_private_dir(parent)?;
    let original = read_config(path)?;
    let updated = rewrite(&original, path, alias, host, replace)?;
    ensure!(
        updated.len() as u64 <= MAX_CONFIG_BYTES,
        "SSH config exceeds 1 MiB"
    );
    let temporary = parent.join(format!(".sloosh-config-{:016x}", rand::random::<u64>()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(updated.as_bytes())?;
        file.sync_all()?;
        ensure!(
            read_config(path)? == original,
            "SSH config changed during editing; reload before saving"
        );
        std::fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn host() -> HostSummary {
        HostSummary {
            alias: "app".into(),
            hostname: "app.example".into(),
            port: Some(2222),
            user: Some("deploy".into()),
            auth: HostAuthKind::Agent,
            route: HostRoute::ProxyJump {
                spec: "jump".into(),
            },
        }
    }

    #[test]
    fn system_edits_preserve_other_hosts_comments_and_identity_settings() {
        let original = "# keep\nHost app\n  HostName old\n  User old\n  IdentityFile ~/.ssh/id_ed25519\n  # key comment\nHost jump\n  HostName gateway\n";
        let updated = rewrite(
            original,
            Path::new("/fixture/config"),
            "app",
            Some(&host()),
            true,
        )
        .unwrap();
        assert!(updated.starts_with("# keep\nHost app\n"));
        assert!(updated.contains("  IdentityFile ~/.ssh/id_ed25519\n  # key comment\n"));
        assert!(updated.ends_with("Host jump\n  HostName gateway\n"));
        assert!(!updated.contains("HostName old"));
    }

    #[test]
    fn new_stanza_preserves_global_defaults_for_other_hosts() {
        let original = "User global\nHost other\n HostName other.example\n";
        let updated = rewrite(
            original,
            Path::new("/fixture/config"),
            "app",
            Some(&host()),
            false,
        )
        .unwrap();
        let config = SshConfig::parse(&updated);
        assert_eq!(config.resolve("other").user, "global");
        assert_eq!(config.resolve("app").user, "deploy");
        assert_eq!(config.resolve("app").proxy_jump.as_deref(), Some("jump"));
    }

    #[test]
    fn system_edits_reject_shared_blocks_overrides_and_injection() {
        for original in [
            "Host app other\n",
            "Host app\nHost app\n",
            "User earlier\nHost app\n",
        ] {
            assert!(
                rewrite(
                    original,
                    Path::new("/fixture/config"),
                    "app",
                    Some(&host()),
                    true
                )
                .is_err()
            );
        }
        let mut bad = host();
        bad.hostname = "host\nProxyCommand bad".into();
        assert!(rewrite("", Path::new("/fixture/config"), "app", Some(&bad), false).is_err());
        assert_eq!(
            SshConfig::parse("Host *\nHost app other\nHost !blocked\n").aliases(),
            vec!["app", "other"]
        );
    }
}
