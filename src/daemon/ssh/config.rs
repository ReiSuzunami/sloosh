//! OpenSSH client-config subset owned by Sloosh.
//!
//! This module is intentionally mechanical: it parses and resolves the
//! documented directives without performing vault lookup, route expansion,
//! network I/O, authentication, or lease checks.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use tracing::warn;

/// A resolved `IdentityAgent` directive value (ssh_config(5)): either a
/// specific agent socket path to connect to instead of `$SSH_AUTH_SOCK`, or
/// an explicit `none` to disable agent auth entirely for the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityAgentValue {
    Path(PathBuf),
    Disabled,
}

/// One `Host` block from `~/.ssh/config`, holding only the directives
/// `docs/internals/architecture.md` promises to understand.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct HostBlock {
    patterns: Vec<String>,
    hostname: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    identity_files: Vec<PathBuf>,
    proxy_jump: Option<String>,
    identity_agent: Option<IdentityAgentValue>,
}

/// A parsed `~/.ssh/config` subset. Block order preserves OpenSSH's
/// first-value-wins semantics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshConfig {
    blocks: Vec<HostBlock>,
}

/// Resolved connection parameters after merging matching config blocks over
/// the documented defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostConfig {
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<PathBuf>,
    pub proxy_jump: Option<String>,
    pub identity_agent: Option<IdentityAgentValue>,
}

fn warned_directives() -> &'static Mutex<HashSet<String>> {
    static WARNED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    WARNED.get_or_init(|| Mutex::new(HashSet::new()))
}

fn warn_unknown_directive_once(directive: &str) {
    let key = directive.to_ascii_lowercase();
    let mut seen = warned_directives()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if seen.insert(key) {
        warn!(
            directive,
            "unrecognized ~/.ssh/config directive; sloosh only understands Host/HostName/Port/User/\
             IdentityFile/ProxyJump/IdentityAgent — ignoring this line rather than guessing what it \
             means"
        );
    }
}

impl SshConfig {
    /// Parse the supported directives. Invalid or unknown lines are warned
    /// about and skipped rather than making all SSH configuration unusable.
    pub fn parse(contents: &str) -> Self {
        let mut blocks = Vec::new();
        let mut current: Option<HostBlock> = None;

        for raw_line in contents.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((directive, rest)) = split_directive(line) else {
                continue;
            };
            let rest = rest.trim();

            match directive.to_ascii_lowercase().as_str() {
                "host" => {
                    if let Some(block) = current.take() {
                        blocks.push(block);
                    }
                    current = Some(HostBlock {
                        patterns: rest.split_whitespace().map(str::to_string).collect(),
                        ..Default::default()
                    });
                }
                "hostname" => with_current(&mut current, |block| {
                    block.hostname = Some(rest.to_string());
                }),
                "port" => with_current(&mut current, |block| match rest.parse::<u16>() {
                    Ok(port) => block.port = Some(port),
                    Err(_) => warn!(value = rest, "ignoring unparsable Port directive"),
                }),
                "user" => with_current(&mut current, |block| {
                    block.user = Some(rest.to_string());
                }),
                "identityfile" => with_current(&mut current, |block| {
                    block.identity_files.push(expand_tilde(rest));
                }),
                "proxyjump" => with_current(&mut current, |block| {
                    if !rest.eq_ignore_ascii_case("none") {
                        block.proxy_jump = Some(rest.to_string());
                    }
                }),
                "identityagent" => with_current(&mut current, |block| {
                    block.identity_agent = Some(parse_identity_agent_value(rest));
                }),
                other => warn_unknown_directive_once(other),
            }
        }
        if let Some(block) = current {
            blocks.push(block);
        }
        Self { blocks }
    }

    /// Load the default config path. A missing file is equivalent to an empty
    /// config; other read failures are logged and also fall back to empty.
    pub fn load_default() -> Self {
        let path = ssh_config_path();
        match std::fs::read_to_string(&path) {
            Ok(contents) => Self::parse(&contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(error) => {
                warn!(path = %path.display(), %error, "failed to read ~/.ssh/config, proceeding as if empty");
                Self::default()
            }
        }
    }

    /// Resolve an alias using OpenSSH-style first-value-wins semantics.
    pub fn resolve(&self, alias: &str) -> HostConfig {
        let (user_override, host_key) = match alias.rsplit_once('@') {
            Some((user, host)) if !user.is_empty() && !host.is_empty() => (Some(user), host),
            _ => (None, alias),
        };
        let mut config = HostConfig {
            alias: alias.to_string(),
            hostname: host_key.to_string(),
            port: 22,
            user: user_override
                .map(str::to_string)
                .unwrap_or_else(current_user),
            identity_files: Vec::new(),
            proxy_jump: None,
            identity_agent: None,
        };
        let mut hostname_set = false;
        let mut port_set = false;
        let mut user_set = user_override.is_some();
        let mut proxy_jump_set = false;
        let mut identity_agent_set = false;

        for block in &self.blocks {
            if !host_patterns_match(&block.patterns, host_key) {
                continue;
            }
            if !hostname_set {
                if let Some(hostname) = &block.hostname {
                    config.hostname.clone_from(hostname);
                    hostname_set = true;
                }
            }
            if !port_set {
                if let Some(port) = block.port {
                    config.port = port;
                    port_set = true;
                }
            }
            if !user_set {
                if let Some(user) = &block.user {
                    config.user.clone_from(user);
                    user_set = true;
                }
            }
            if !proxy_jump_set {
                if let Some(proxy_jump) = &block.proxy_jump {
                    config.proxy_jump = Some(proxy_jump.clone());
                    proxy_jump_set = true;
                }
            }
            if !identity_agent_set {
                if let Some(identity_agent) = &block.identity_agent {
                    config.identity_agent = Some(identity_agent.clone());
                    identity_agent_set = true;
                }
            }
            config
                .identity_files
                .extend(block.identity_files.iter().cloned());
        }
        config
    }
}

fn parse_identity_agent_value(raw: &str) -> IdentityAgentValue {
    let unquoted = unquote(raw);
    if unquoted.eq_ignore_ascii_case("none") {
        IdentityAgentValue::Disabled
    } else {
        IdentityAgentValue::Path(expand_tilde(&unquoted))
    }
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

fn with_current(current: &mut Option<HostBlock>, update: impl FnOnce(&mut HostBlock)) {
    match current {
        Some(block) => update(block),
        None => warn!("directive outside any Host block in ~/.ssh/config; ignoring"),
    }
}

fn split_directive(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if let Some(index) = line.find(char::is_whitespace) {
        Some((&line[..index], line[index..].trim_start()))
    } else if let Some(index) = line.find('=') {
        Some((&line[..index], line[index + 1..].trim_start()))
    } else if line.is_empty() {
        None
    } else {
        Some((line, ""))
    }
}

pub(super) fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        home_dir().join(rest)
    } else if path == "~" {
        home_dir()
    } else {
        PathBuf::from(path)
    }
}

pub(super) fn home_dir() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()))
}

fn ssh_config_path() -> PathBuf {
    home_dir().join(".ssh").join("config")
}

pub(super) fn current_user() -> String {
    if let Ok(user) = std::env::var("USER") {
        if !user.is_empty() {
            return user;
        }
    }
    if let Ok(user) = std::env::var("LOGNAME") {
        if !user.is_empty() {
            return user;
        }
    }
    // SAFETY: getuid/getpwuid are plain libc lookups with no preconditions;
    // the returned pointer is read immediately.
    unsafe {
        let uid = libc::getuid();
        let passwd = libc::getpwuid(uid);
        if !passwd.is_null() {
            let name = std::ffi::CStr::from_ptr((*passwd).pw_name);
            if let Ok(user) = name.to_str() {
                return user.to_string();
            }
        }
    }
    "root".to_string()
}

pub(super) fn host_patterns_match(patterns: &[String], alias: &str) -> bool {
    let mut matched = false;
    for pattern in patterns {
        if let Some(negated) = pattern.strip_prefix('!') {
            if glob_match(negated, alias) {
                return false;
            }
        } else if glob_match(pattern, alias) {
            matched = true;
        }
    }
    matched
}

pub(super) fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    glob_match_inner(&pattern, &text)
}

fn glob_match_inner(pattern: &[char], text: &[char]) -> bool {
    match pattern.first() {
        None => text.is_empty(),
        Some('*') => {
            glob_match_inner(&pattern[1..], text)
                || (!text.is_empty() && glob_match_inner(pattern, &text[1..]))
        }
        Some('?') => !text.is_empty() && glob_match_inner(&pattern[1..], &text[1..]),
        Some(character) => {
            !text.is_empty() && text[0] == *character && glob_match_inner(&pattern[1..], &text[1..])
        }
    }
}
