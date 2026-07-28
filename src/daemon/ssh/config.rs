//! OpenSSH client-config subset owned by Sloosh.
//!
//! This module is intentionally mechanical: it parses and resolves the
//! documented directives without performing vault lookup, route expansion,
//! network I/O, authentication, or lease checks.

use std::collections::BTreeSet;
use std::path::PathBuf;

use tracing::warn;

use crate::diagnostics::{WarningAction, warning_occurrence};

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
    diagnostics: Vec<SshConfigDiagnostic>,
}

/// A parsed `~/.ssh/config` subset. Block order preserves OpenSSH's
/// first-value-wins semantics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshConfig {
    blocks: Vec<HostBlock>,
}

/// A parser diagnostic stores only source location and normalized directive
/// name. Directive values are deliberately excluded because they may contain
/// paths, commands, tokens, or other local secrets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct SshConfigDiagnostic {
    line: usize,
    kind: SshConfigDiagnosticKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SshConfigDiagnosticKind {
    UnsupportedDirective { directive: String },
    InvalidPort,
    ReadFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SshConfigError {
    #[error(
        "~/.ssh/config line {line} has an invalid Port value. Sloosh refuses to guess port 22; \
         fix or remove that Port directive."
    )]
    InvalidPort { line: usize },
    #[error(
        "~/.ssh/config line {line} uses unsupported directive {directive}. Sloosh cannot safely \
         ignore it for this host; use a vault-managed profile or simplify that Host route."
    )]
    UnsupportedDirective { line: usize, directive: String },
    #[error(
        "Sloosh could not read ~/.ssh/config and refuses to guess connection settings. Fix its \
         ownership and permissions, or use a vault-managed profile."
    )]
    ReadFailure,
}

impl SshConfigError {
    pub fn directive(&self) -> &str {
        match self {
            Self::InvalidPort { .. } => "port",
            Self::UnsupportedDirective { directive, .. } => directive,
            Self::ReadFailure => "config",
        }
    }

    pub fn line(&self) -> usize {
        match self {
            Self::InvalidPort { line } | Self::UnsupportedDirective { line, .. } => *line,
            Self::ReadFailure => 0,
        }
    }
}

impl SshConfigDiagnostic {
    pub(super) fn directive(&self) -> &str {
        match &self.kind {
            SshConfigDiagnosticKind::UnsupportedDirective { directive } => directive,
            SshConfigDiagnosticKind::InvalidPort => "port",
            SshConfigDiagnosticKind::ReadFailure => "config",
        }
    }

    pub(super) fn line(&self) -> usize {
        self.line
    }
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

impl SshConfig {
    /// Parse the supported directives. Invalid or unknown lines are retained
    /// as target-scoped diagnostics and skipped. Parsing itself never logs:
    /// callers decide whether the selected host actually depends on this
    /// config before surfacing anything.
    pub fn parse(contents: &str) -> Self {
        // OpenSSH permits defaults before the first Host block. Model those
        // as an initial `Host *` block so first-value-wins remains mechanical.
        let mut blocks = vec![HostBlock {
            patterns: vec!["*".to_string()],
            ..Default::default()
        }];
        let mut current: Option<HostBlock> = None;
        let mut inside_unsupported_match = false;

        for (line_index, raw_line) in contents.lines().enumerate() {
            let line_number = line_index + 1;
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((directive, rest)) = split_directive(line) else {
                continue;
            };
            let rest = rest.trim();
            let normalized = directive.to_ascii_lowercase();

            if normalized == "match" {
                if let Some(block) = current.take() {
                    blocks.push(block);
                }
                // Match starts a new conditional section rather than nesting
                // inside the preceding Host block. Because Sloosh does not
                // evaluate Match predicates, it cannot prove that any
                // config-backed alias is unaffected. Keep this as a global
                // fail-closed barrier; the ignored body ends at the next Host.
                blocks[0].diagnostics.push(SshConfigDiagnostic {
                    line: line_number,
                    kind: SshConfigDiagnosticKind::UnsupportedDirective {
                        directive: normalized,
                    },
                });
                inside_unsupported_match = true;
                continue;
            }

            match normalized.as_str() {
                "host" => {
                    if let Some(block) = current.take() {
                        blocks.push(block);
                    }
                    inside_unsupported_match = false;
                    current = Some(HostBlock {
                        patterns: rest.split_whitespace().map(str::to_string).collect(),
                        ..Default::default()
                    });
                }
                _ if inside_unsupported_match => {}
                "hostname" => with_current_or_global(&mut current, &mut blocks[0], |block| {
                    block.hostname = Some(rest.to_string());
                }),
                "port" => {
                    with_current_or_global(&mut current, &mut blocks[0], |block| {
                        match rest.parse::<u16>() {
                            Ok(port) => block.port = Some(port),
                            Err(_) => block.diagnostics.push(SshConfigDiagnostic {
                                line: line_number,
                                kind: SshConfigDiagnosticKind::InvalidPort,
                            }),
                        }
                    });
                }
                "user" => with_current_or_global(&mut current, &mut blocks[0], |block| {
                    block.user = Some(rest.to_string());
                }),
                "identityfile" => with_current_or_global(&mut current, &mut blocks[0], |block| {
                    block.identity_files.push(expand_tilde(rest));
                }),
                "proxyjump" => with_current_or_global(&mut current, &mut blocks[0], |block| {
                    if !rest.eq_ignore_ascii_case("none") {
                        block.proxy_jump = Some(rest.to_string());
                    }
                }),
                "identityagent" => with_current_or_global(&mut current, &mut blocks[0], |block| {
                    block.identity_agent = Some(parse_identity_agent_value(rest));
                }),
                other => {
                    with_current_or_global(&mut current, &mut blocks[0], |block| {
                        block.diagnostics.push(SshConfigDiagnostic {
                            line: line_number,
                            kind: SshConfigDiagnosticKind::UnsupportedDirective {
                                directive: other.to_string(),
                            },
                        });
                    });
                }
            }
        }
        if let Some(block) = current {
            blocks.push(block);
        }
        Self { blocks }
    }

    /// Diagnostics that can affect `alias`: global directives plus directives
    /// from matching Host blocks. Unknown directives in unrelated blocks stay
    /// silent.
    pub(super) fn diagnostics_for(&self, alias: &str) -> Vec<&SshConfigDiagnostic> {
        let host_key = alias
            .rsplit_once('@')
            .filter(|(user, host)| !user.is_empty() && !host.is_empty())
            .map_or(alias, |(_, host)| host);
        self.blocks
            .iter()
            .filter(|block| host_patterns_match(&block.patterns, host_key))
            .flat_map(|block| block.diagnostics.iter())
            .collect()
    }

    /// Emit one concise warning per diagnostic class for a selected
    /// SSH-config host. The dedupe key includes the target and source
    /// location, but those values stay out of the log payload.
    pub(super) fn warn_diagnostics_for(&self, alias: &str) {
        let mut unsupported = BTreeSet::new();
        let mut lines = BTreeSet::new();
        let mut suppressed_total = 0_u64;
        for diagnostic in self.diagnostics_for(alias) {
            if diagnostic.connection_error().is_some() {
                continue;
            }
            let SshConfigDiagnosticKind::UnsupportedDirective { directive } = &diagnostic.kind
            else {
                continue;
            };
            let scope = (alias, diagnostic.line(), diagnostic.directive());
            if let WarningAction::Emit { suppressed } =
                warning_occurrence("SSH_CONFIG_UNSUPPORTED_DIRECTIVE", &scope)
            {
                suppressed_total = suppressed_total.saturating_add(suppressed);
                unsupported.insert(directive.as_str());
                lines.insert(diagnostic.line());
            }
        }

        if !unsupported.is_empty() {
            let directives = unsupported.into_iter().collect::<Vec<_>>().join(",");
            let lines = join_line_numbers(&lines);
            warn!(
                diagnostic_code = "SSH_CONFIG_UNSUPPORTED_DIRECTIVE",
                directives,
                lines,
                suppressed = suppressed_total,
                "selected SSH config contains unsupported directives; ignoring only those \
                 directives"
            );
        }
    }

    /// Resolve a host for an actual connection. Diagnostics that could change
    /// endpoint, route, trust identity, or port fail closed; lower-impact
    /// unsupported options are warned once and ignored.
    pub(super) fn resolve_for_connection(&self, alias: &str) -> Result<HostConfig, SshConfigError> {
        if let Some(error) = self
            .diagnostics_for(alias)
            .into_iter()
            .find_map(SshConfigDiagnostic::connection_error)
        {
            return Err(error);
        }
        self.warn_diagnostics_for(alias);
        Ok(self.resolve(alias))
    }

    /// Load the default config path. A missing file is equivalent to an empty
    /// config; other read failures become deferred diagnostics so a direct
    /// vault profile remains independent while a config-backed host fails.
    pub fn load_default() -> Self {
        let path = ssh_config_path();
        match std::fs::read_to_string(&path) {
            Ok(contents) => Self::parse(&contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(_) => Self {
                blocks: vec![HostBlock {
                    patterns: vec!["*".to_string()],
                    diagnostics: vec![SshConfigDiagnostic {
                        line: 0,
                        kind: SshConfigDiagnosticKind::ReadFailure,
                    }],
                    ..Default::default()
                }],
            },
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

impl SshConfigDiagnostic {
    fn connection_error(&self) -> Option<SshConfigError> {
        match &self.kind {
            SshConfigDiagnosticKind::InvalidPort => {
                Some(SshConfigError::InvalidPort { line: self.line })
            }
            SshConfigDiagnosticKind::ReadFailure => Some(SshConfigError::ReadFailure),
            SshConfigDiagnosticKind::UnsupportedDirective { directive }
                if is_connection_critical_directive(directive) =>
            {
                Some(SshConfigError::UnsupportedDirective {
                    line: self.line,
                    directive: directive.clone(),
                })
            }
            SshConfigDiagnosticKind::UnsupportedDirective { .. } => None,
        }
    }
}

fn is_connection_critical_directive(directive: &str) -> bool {
    matches!(
        directive,
        "match"
            | "include"
            | "proxycommand"
            | "proxyusefdpass"
            | "hostkeyalias"
            | "canonicalizehostname"
            | "canonicaldomains"
    )
}

fn join_line_numbers(lines: &BTreeSet<usize>) -> String {
    lines
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
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

fn with_current_or_global(
    current: &mut Option<HostBlock>,
    global: &mut HostBlock,
    update: impl FnOnce(&mut HostBlock),
) {
    match current {
        Some(block) => update(block),
        None => update(global),
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

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn diagnostics_only_include_global_and_matching_host_blocks() {
        let config = SshConfig::parse(
            "\
Include ~/.ssh/conf.d/*
Host other
    ProxyCommand secret-helper --token should-not-be-logged
Host fac
    IdentitiesOnly yes
",
        );

        let diagnostics = config.diagnostics_for("fac");
        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics[0].directive(), "include");
        assert_eq!(diagnostics[0].line(), 1);
        assert_eq!(diagnostics[1].directive(), "identitiesonly");
        assert_eq!(diagnostics[1].line(), 5);

        let rendered = format!("{diagnostics:?}");
        assert!(!rendered.contains("should-not-be-logged"));
        assert!(!rendered.contains("secret-helper"));
        assert!(!rendered.contains("~/.ssh/conf.d"));
    }

    #[test]
    fn global_include_fails_closed_without_exposing_its_value() {
        let config = SshConfig::parse(
            "\
Include ~/.ssh/conf.d/private-*.conf
Host fac
    User deploy
",
        );

        let error = config.resolve_for_connection("fac").unwrap_err();
        assert_eq!(error.directive(), "include");
        assert_eq!(error.line(), 1);
        assert!(!error.to_string().contains("private"));
        assert!(!error.to_string().contains("conf.d"));
    }

    #[test]
    fn include_inside_an_unrelated_host_block_stays_scoped() {
        let config = SshConfig::parse(
            "\
Host other
    Include ~/.ssh/conf.d/private-*.conf
Host fac
    User deploy
",
        );

        assert!(config.resolve_for_connection("fac").is_ok());
        let error = config.resolve_for_connection("other").unwrap_err();
        assert_eq!(error.directive(), "include");
        assert_eq!(error.line(), 2);
    }

    #[test]
    fn match_is_a_global_safety_barrier_not_part_of_the_previous_host() {
        let config = SshConfig::parse(
            "\
Host other
    User deploy
Match host other
    ProxyJump secret-bastion
Host fac
    User deploy
",
        );

        let error = config.resolve_for_connection("fac").unwrap_err();
        assert_eq!(error.directive(), "match");
        assert_eq!(error.line(), 3);
        assert!(!error.to_string().contains("secret-bastion"));
    }

    #[test]
    fn connection_critical_config_diagnostics_fail_only_matching_hosts() {
        let config = SshConfig::parse(
            "\
Host other
    Port 99999
Host fac
    User deploy
",
        );

        assert!(config.resolve_for_connection("fac").is_ok());
        let error = config.resolve_for_connection("other").unwrap_err();
        assert_eq!(error.line(), 2);
        assert_eq!(error.directive(), "port");
        assert!(!error.to_string().contains("99999"));
    }

    #[test]
    fn critical_directive_error_names_directive_without_value() {
        let config = SshConfig::parse(
            "Host fac\n    ProxyCommand /Users/private/bin/secret-helper --token hidden\n",
        );

        let error = config.resolve_for_connection("fac").unwrap_err();
        assert_eq!(error.directive(), "proxycommand");
        assert_eq!(error.line(), 2);
        assert!(!error.to_string().contains("/Users/private"));
    }
}
