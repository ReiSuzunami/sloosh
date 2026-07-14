//! SSH connection establishment via `russh`, `~/.ssh/config` subset parsing
//! (`Host`, `HostName`, `Port`, `User`, `IdentityFile`, `ProxyJump`,
//! `IdentityAgent`), and `known_hosts` handling (docs/internals/architecture.md).
//!
//! Authorization gate (docs/internals/architecture.md): lease enforcement for the *target* host
//! happens one layer up in `daemon/mod.rs`, before any of this module's
//! connection logic runs — by the time `connect`/`connect_resolved` are
//! reached, the caller has already proven a human approved access to the
//! target. What lives here is purely mechanical: resolve connection
//! parameters (vault entries take precedence over `~/.ssh/config` for a
//! given alias — docs/internals/architecture.md), verify the host key, and authenticate
//! (ssh-agent, then unencrypted `IdentityFile` keys, then — only while the
//! vault's derived key is cached, i.e. at least one lease is active — the
//! vault's stored password).
//!
//! **ProxyJump chains** (docs/internals/architecture.md): a `ProxyJump` spec may name
//! several comma-separated hops, and any hop may itself have its own
//! `ProxyJump` (vault `jump` field or `~/.ssh/config` directive), expanded
//! recursively up to [`MAX_PROXY_JUMP_HOPS`] hops with cycle detection by
//! resolved alias. Each hop is dialed in turn over a `direct-tcpip` channel
//! opened on the previous hop's connection, exactly like the single-hop case.
//! Unlike the target, a jump hop's own lease is checked *here*, right before
//! it's dialed (`ensure_hop_leased`) — but only if the hop's credentials
//! actually come from the vault; a hop resolved purely from
//! `~/.ssh/config` uses ambient user credentials and needs no lease, same as
//! today.

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use russh::Pty;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKey};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, warn};
use zeroize::Zeroize;

use crate::daemon::lease;
use crate::daemon::vault;
use crate::transport::unix::sloosh_home;

/// Hard cap on ProxyJump chain length (docs/internals/architecture.md), counting every hop
/// pulled in transitively by a jump host's own `ProxyJump` (vault `jump`
/// field or `~/.ssh/config` directive). Matches OpenSSH's own default
/// `MAX_PROXY_JUMP` bound in spirit — deep chains are almost always a
/// misconfigured loop, not a real topology.
const MAX_PROXY_JUMP_HOPS: usize = 8;
const FORWARD_TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Everything that can go wrong establishing an SSH connection. Variants
/// carry self-teaching messages (docs/internals/architecture.md): the human reading a CLI
/// error should know what to do next without consulting docs.
#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error(
        "could not resolve host '{host}' — check the name for typos, or map the alias to a real \
         address with a `Host {host}` + `HostName` entry in ~/.ssh/config. (dns: {source})"
    )]
    HostResolution {
        host: String,
        source: std::io::Error,
    },

    #[error(
        "connection to {host}:{port} was refused — the host is reachable but nothing is \
         listening on that port. Check that sshd is running there and that the Port in \
         ~/.ssh/config is right. (tcp: {source})"
    )]
    ConnectRefused {
        host: String,
        port: u16,
        source: std::io::Error,
    },

    #[error(
        "timed out connecting to {host}:{port} — the host may be down, unreachable from this \
         network, or firewalled. Try `ssh {host}` by hand to compare. (tcp: {source})"
    )]
    ConnectTimeout {
        host: String,
        port: u16,
        source: std::io::Error,
    },

    #[error(
        "failed to connect to {host}:{port} — check network reachability and firewall rules, \
         and try `ssh {host}` by hand to compare. (tcp: {source})"
    )]
    Connect {
        host: String,
        port: u16,
        source: std::io::Error,
    },

    #[error(
        "SSH handshake with {host}:{port} failed before authentication — whatever answered on \
         that port closed or rejected the connection, so it may not be an SSH server at all \
         (wrong port? captive proxy?). Try `ssh {host}` by hand to see what answers. \
         (russh: {source})"
    )]
    Handshake {
        host: String,
        port: u16,
        source: russh::Error,
    },

    #[error(
        "the jump host connected, but could not open a tunnel to {host}:{port} — the target may \
         be unreachable from the jump host, or the jump host forbids TCP forwarding \
         (AllowTcpForwarding). Try `ssh -J <jump> {host}` by hand to compare. (russh: {source})"
    )]
    ProxyTunnel {
        host: String,
        port: u16,
        source: russh::Error,
    },

    #[error(
        "host key for {host}:{port} is not in ~/.ssh/known_hosts or ~/.sloosh/known_hosts, so \
         sloosh refuses to trust it. If this host is in the vault, its key is normally recorded \
         automatically the first time `sloosh approve` grants access to it; otherwise run \
         `ssh {host}` by hand once, accept and record its fingerprint, then retry."
    )]
    UnknownHostKey { host: String, port: u16 },

    #[error(
        "REFUSING TO CONNECT: the host key presented by {host}:{port} does NOT match the one \
         recorded in known_hosts (line {line}). This usually means the host was reinstalled, \
         OR that you are the target of a man-in-the-middle attack. sloosh will not proceed \
         automatically — verify out of band and update known_hosts yourself if the change is expected."
    )]
    HostKeyMismatch {
        host: String,
        port: u16,
        line: usize,
    },

    #[error(
        "could not check the server's key against known_hosts — make sure ~/.ssh/known_hosts \
         and ~/.sloosh/known_hosts exist and are readable, then retry. (keys: {0})"
    )]
    KnownHosts(#[from] russh::keys::Error),

    #[error(
        "identity file {path} is passphrase-protected; sloosh never prompts for key passphrases. \
         Add it to ssh-agent first (`ssh-add {path}`) and sloosh will pick it up automatically."
    )]
    EncryptedIdentity { path: PathBuf },

    #[error(
        "no working authentication method for {host} (tried ssh-agent identities, unencrypted \
         IdentityFile keys from ~/.ssh/config, and a vault password if '{host}' has one). Load a \
         key into ssh-agent with `ssh-add`, add an `IdentityFile` entry to ~/.ssh/config, or \
         `sloosh add {host} --hostname <h>` to store a password in the vault."
    )]
    AuthFailed { host: String },

    #[error(
        "the ProxyJump chain for this host is too deep ({limit} hops max, including hops pulled \
         in by a jump host's own ProxyJump) — sloosh refuses to dial an unbounded chain. Simplify \
         the `ProxyJump` entries involved, or connect through fewer nested jump hosts."
    )]
    ProxyJumpTooDeep { limit: usize },

    #[error(
        "the ProxyJump chain for this host revisits '{alias}' — that's a cycle (a jump host, \
         directly or through its own ProxyJump, eventually points back at an alias already in the \
         chain), so there is no finite path to dial. Check `~/.ssh/config` (and any vault `jump` \
         fields) for a ProxyJump loop involving '{alias}'."
    )]
    ProxyJumpCycle { alias: String },

    #[error(
        "jump host '{hop}' is vault-backed and needs its own lease; run: sloosh request {target} \
         {hop}"
    )]
    JumpHostLeaseRequired { hop: String, target: String },

    /// Catch-all for `russh` protocol errors on an already-established
    /// connection (channel opens, PTY/shell requests, writes). Never let
    /// this be the bare underlying message (docs/internals/architecture.md): say what it
    /// means and what to try, with the raw error as parenthetical detail.
    #[error(
        "the SSH connection failed mid-operation and is no longer usable — retry the command \
         (a fresh connection will be made), and if it keeps happening run `ssh -v <host>` by \
         hand to see what the server reports. (russh: {0})"
    )]
    Russh(#[from] russh::Error),
}

// ---------------------------------------------------------------------------
// `~/.ssh/config` subset parser
// ---------------------------------------------------------------------------

/// A resolved `IdentityAgent` directive value (ssh_config(5)): either a
/// specific agent socket path to connect to instead of `$SSH_AUTH_SOCK`, or
/// an explicit `none` to disable agent auth entirely for the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityAgentValue {
    Path(PathBuf),
    Disabled,
}

/// One `Host` block from `~/.ssh/config`, holding only the directives
/// docs/internals/architecture.md promises to understand.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct HostBlock {
    /// Raw patterns as written after `Host` (may contain `*`/`?` globs and
    /// `!negated` entries).
    patterns: Vec<String>,
    hostname: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    identity_files: Vec<PathBuf>,
    proxy_jump: Option<String>,
    identity_agent: Option<IdentityAgentValue>,
}

/// A parsed `~/.ssh/config` subset: an ordered list of `Host` blocks. Order
/// matters — like real `ssh_config`, the *first* matching block's value for
/// a given directive wins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshConfig {
    blocks: Vec<HostBlock>,
}

/// Resolved connection parameters for a host alias, after merging any
/// matching `~/.ssh/config` blocks over the built-in defaults documented in
/// `docs/internals/architecture.md`: literal hostname, local user, port 22.
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

/// Warn once per unknown directive name for the lifetime of the process
/// (docs/internals/architecture.md: "未知指令警告而非静默忽略" — warn, don't silently drop, but
/// don't spam the log on every reconnect either).
fn warned_directives() -> &'static Mutex<HashSet<String>> {
    static WARNED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    WARNED.get_or_init(|| Mutex::new(HashSet::new()))
}

fn warn_unknown_directive_once(directive: &str) {
    let key = directive.to_ascii_lowercase();
    let mut seen = warned_directives()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
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
    /// Parse the subset of `~/.ssh/config` directives docs/internals/architecture.md promises.
    /// Never fails: unparsable lines are warned about (see
    /// `warn_unknown_directive_once`) and skipped, matching real `ssh`'s
    /// tolerance for config quirks.
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
                "hostname" => with_current(&mut current, |b| b.hostname = Some(rest.to_string())),
                "port" => with_current(&mut current, |b| match rest.parse::<u16>() {
                    Ok(p) => b.port = Some(p),
                    Err(_) => warn!(value = rest, "ignoring unparsable Port directive"),
                }),
                "user" => with_current(&mut current, |b| b.user = Some(rest.to_string())),
                "identityfile" => with_current(&mut current, |b| {
                    b.identity_files.push(expand_tilde(rest));
                }),
                "proxyjump" => with_current(&mut current, |b| {
                    if !rest.eq_ignore_ascii_case("none") {
                        b.proxy_jump = Some(rest.to_string());
                    }
                }),
                "identityagent" => with_current(&mut current, |b| {
                    b.identity_agent = Some(parse_identity_agent_value(rest));
                }),
                other => warn_unknown_directive_once(other),
            }
        }
        if let Some(block) = current.take() {
            blocks.push(block);
        }
        SshConfig { blocks }
    }

    /// Load and parse `~/.ssh/config`. Missing file is not an error (most
    /// hosts have none) — it just means every alias resolves to defaults.
    pub fn load_default() -> Self {
        let path = ssh_config_path();
        match std::fs::read_to_string(&path) {
            Ok(contents) => Self::parse(&contents),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to read ~/.ssh/config, proceeding as if empty");
                Self::default()
            }
        }
    }

    /// Resolve `alias` against this config, falling back to the documented
    /// defaults (literal hostname, local user, port 22) for anything no
    /// matching block sets.
    ///
    /// A `user@host` literal is split like an OpenSSH destination: the host
    /// part is what gets matched against `Host` patterns (and becomes the
    /// default hostname), and the user part wins over any config `User` —
    /// the same precedence real `ssh user@host` gives the command line.
    /// `cfg.alias` keeps the full literal, since leases and sessions are
    /// keyed by whatever string the caller used.
    pub fn resolve(&self, alias: &str) -> HostConfig {
        let (user_override, host_key) = match alias.rsplit_once('@') {
            Some((user, host)) if !user.is_empty() && !host.is_empty() => (Some(user), host),
            _ => (None, alias),
        };
        let mut cfg = HostConfig {
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
                if let Some(h) = &block.hostname {
                    cfg.hostname = h.clone();
                    hostname_set = true;
                }
            }
            if !port_set {
                if let Some(p) = block.port {
                    cfg.port = p;
                    port_set = true;
                }
            }
            if !user_set {
                if let Some(u) = &block.user {
                    cfg.user = u.clone();
                    user_set = true;
                }
            }
            if !proxy_jump_set {
                if let Some(pj) = &block.proxy_jump {
                    cfg.proxy_jump = Some(pj.clone());
                    proxy_jump_set = true;
                }
            }
            if !identity_agent_set {
                if let Some(ia) = &block.identity_agent {
                    cfg.identity_agent = Some(ia.clone());
                    identity_agent_set = true;
                }
            }
            // IdentityFile is cumulative across matching blocks, like real ssh_config.
            cfg.identity_files
                .extend(block.identity_files.iter().cloned());
        }
        cfg
    }
}

/// Parse an `IdentityAgent` value: `none` (disable agent auth), or a path
/// (optionally double-quoted, tilde-expanded like `IdentityFile`).
fn parse_identity_agent_value(raw: &str) -> IdentityAgentValue {
    let unquoted = unquote(raw);
    if unquoted.eq_ignore_ascii_case("none") {
        IdentityAgentValue::Disabled
    } else {
        IdentityAgentValue::Path(expand_tilde(&unquoted))
    }
}

/// Strip one layer of surrounding double quotes, if present — ssh_config(5)
/// allows quoting any directive value that contains whitespace.
fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn with_current(current: &mut Option<HostBlock>, f: impl FnOnce(&mut HostBlock)) {
    match current {
        Some(block) => f(block),
        None => warn!("directive outside any Host block in ~/.ssh/config; ignoring"),
    }
}

/// Split `"Key value"` or `"Key=value"` (both are valid ssh_config syntax)
/// into `(key, value)`.
fn split_directive(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if let Some(idx) = line.find(char::is_whitespace) {
        Some((&line[..idx], line[idx..].trim_start()))
    } else if let Some(idx) = line.find('=') {
        Some((&line[..idx], line[idx + 1..].trim_start()))
    } else if line.is_empty() {
        None
    } else {
        // A bare keyword with no value (malformed) — still route it through
        // the normal directive dispatch so unknown ones get warned about.
        Some((line, ""))
    }
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        home_dir().join(rest)
    } else if path == "~" {
        home_dir()
    } else {
        PathBuf::from(path)
    }
}

fn home_dir() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()))
}

fn ssh_config_path() -> PathBuf {
    home_dir().join(".ssh").join("config")
}

/// sloosh's own known_hosts file (docs/internals/architecture.md): host keys for vault-backed
/// hosts, auto-recorded during `sloosh approve` after the human confirms the
/// fingerprint. Consulted only after `~/.ssh/known_hosts` comes up empty, so
/// a host the user already trusts via plain `ssh` never needs re-confirming
/// here.
fn sloosh_known_hosts_path() -> PathBuf {
    sloosh_home().join("known_hosts")
}

/// Resolve the local user for the "no config entry" default (docs/internals/architecture.md).
fn current_user() -> String {
    if let Ok(u) = std::env::var("USER") {
        if !u.is_empty() {
            return u;
        }
    }
    if let Ok(u) = std::env::var("LOGNAME") {
        if !u.is_empty() {
            return u;
        }
    }
    // SAFETY: getuid/getpwuid are plain libc lookups with no preconditions;
    // the returned pointer is a static/thread-local buffer we only read
    // through immediately, matching libc's documented contract.
    unsafe {
        let uid = libc::getuid();
        let pw = libc::getpwuid(uid);
        if !pw.is_null() {
            let name = std::ffi::CStr::from_ptr((*pw).pw_name);
            if let Ok(s) = name.to_str() {
                return s.to_string();
            }
        }
    }
    "root".to_string()
}

/// Does `alias` match this `Host` line's pattern list? Supports `*`/`?`
/// globs and `!pattern` negation, per ssh_config(5).
fn host_patterns_match(patterns: &[String], alias: &str) -> bool {
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

/// Minimal shell-glob matcher for `*` (any run of chars, including none)
/// and `?` (exactly one char). No brace/bracket expansion — ssh_config
/// Host patterns don't use them.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_inner(&p, &t)
}

fn glob_match_inner(p: &[char], t: &[char]) -> bool {
    match p.first() {
        None => t.is_empty(),
        Some('*') => {
            glob_match_inner(&p[1..], t) || (!t.is_empty() && glob_match_inner(p, &t[1..]))
        }
        Some('?') => !t.is_empty() && glob_match_inner(&p[1..], &t[1..]),
        Some(c) => !t.is_empty() && t[0] == *c && glob_match_inner(&p[1..], &t[1..]),
    }
}

// ---------------------------------------------------------------------------
// Connection establishment
// ---------------------------------------------------------------------------

/// A live SSH connection: the `russh` handle plus the resolved parameters
/// that were actually used to reach it. Keep this alive for as long as any
/// channel opened on it needs to keep working — dropping it tears down the
/// whole connection (and, transitively, any `ProxyJump` tunnel built on top
/// of it).
pub struct Connection {
    pub handle: russh::client::Handle<Handler>,
    pub resolved: HostConfig,
    /// Kept alive only to hold each `ProxyJump` hop's connection open for as
    /// long as `handle`'s tunneled channel needs it; ordered first-dialed to
    /// last-dialed; never read directly.
    _jumps: Vec<russh::client::Handle<Handler>>,
}

/// Identity of the caller a connection attempt is being made on behalf of,
/// threaded down from `daemon/mod.rs` (where lease enforcement for the
/// *target* host already happened) so that `connect_via_proxy_jump` can
/// apply the same lease check to any vault-backed jump hop along the way
/// (docs/internals/architecture.md).
#[derive(Debug, Clone)]
pub struct LeaseContext {
    pub caller_pid: u32,
    pub lease_token: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ForwardRouteState {
    Pending,
    Active,
    Closed,
}

#[derive(Clone)]
pub(crate) struct ForwardRouteLifecycle {
    state: watch::Sender<ForwardRouteState>,
}

impl ForwardRouteLifecycle {
    pub(crate) fn new() -> Self {
        let (state, _receiver) = watch::channel(ForwardRouteState::Pending);
        Self { state }
    }

    pub(crate) fn state(&self) -> ForwardRouteState {
        *self.state.borrow()
    }

    pub(crate) fn is_active(&self) -> bool {
        self.state() == ForwardRouteState::Active
    }

    pub(crate) fn activate(&self) -> bool {
        self.state.send_if_modified(|state| {
            if *state == ForwardRouteState::Pending {
                *state = ForwardRouteState::Active;
                true
            } else {
                false
            }
        })
    }

    pub(crate) fn close(&self) -> bool {
        self.state.send_if_modified(|state| {
            if *state == ForwardRouteState::Closed {
                false
            } else {
                *state = ForwardRouteState::Closed;
                true
            }
        })
    }

    pub(crate) async fn wait_closed(&self) {
        let mut receiver = self.state.subscribe();
        loop {
            let state = *receiver.borrow_and_update();
            if state == ForwardRouteState::Closed {
                return;
            }
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

/// Where to dial locally when the remote end pushes a `forwarded-tcpip`
/// channel back to us — the `-R` (remote/reverse) forward case. Only ever set
/// on the one [`Connection`] a remote forward owns
/// (`daemon::forward`); a plain session/`-L`-forward connection's [`Handler`]
/// has `route: None`, so [`Handler::server_channel_open_forwarded_tcpip`]
/// falls back to rejecting rather than silently accepting and hanging.
///
/// Deliberately holds only plain, `Clone`-cheap data (no callback/trait
/// object) so `ssh.rs` never needs to depend on `daemon::forward`'s types —
/// `forward.rs` builds one of these and hands it to [`connect_with_route`];
/// `ssh.rs` never looks inside `forward.rs` to construct or interpret it.
#[derive(Clone)]
pub(crate) struct ForwardRoute {
    /// Local host/port to dial for each incoming forwarded connection.
    pub(crate) local_host: String,
    pub(crate) local_port: u16,
    /// Stable authorization selected before the short-lived CLI exits.
    /// Every incoming forwarded connection revalidates and touches it.
    pub(crate) grant: lease::LeaseGrant,
    /// Live tunnel count, shared with the forward's registry entry, for
    /// `forward ls`'s connection-count column.
    pub(crate) tunnel_count: Arc<AtomicUsize>,
    /// Shared Pending -> Active -> Closed gate. Server callbacks may route
    /// channels only while Active; Closed also wakes in-flight work.
    pub(crate) lifecycle: ForwardRouteLifecycle,
}

#[derive(Debug)]
enum ForwardTargetConnectError {
    Closed,
    TimedOut,
    Io(std::io::Error),
}

async fn race_forward_target_connect<T, F>(
    lifecycle: &ForwardRouteLifecycle,
    timeout: Duration,
    connect: F,
) -> Result<T, ForwardTargetConnectError>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    tokio::select! {
        biased;
        _ = lifecycle.wait_closed() => Err(ForwardTargetConnectError::Closed),
        result = tokio::time::timeout(timeout, connect) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(ForwardTargetConnectError::Io(error)),
            Err(_) => Err(ForwardTargetConnectError::TimedOut),
        },
    }
}

/// `russh::client::Handler` doing strict host-key verification against
/// `~/.ssh/known_hosts` (docs/internals/architecture.md "known_hosts hash 条目支持"), plus
/// (only when `route` is set) routing server-initiated `forwarded-tcpip`
/// channels to a local target for `-R` forwards (docs/internals/architecture.md).
pub struct Handler {
    host: String,
    port: u16,
    route: Option<ForwardRoute>,
}

impl russh::client::Handler for Handler {
    type Error = SshError;

    /// Checked against `~/.ssh/known_hosts` first (so anything the user
    /// already trusts via plain `ssh` keeps working untouched), then against
    /// sloosh's own `~/.sloosh/known_hosts` (docs/internals/architecture.md). A mismatch in
    /// either file is a hard refusal — never silently fall through to the
    /// other file once a *different* key has been recorded for this host.
    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool, SshError> {
        match russh::keys::check_known_hosts(&self.host, self.port, server_public_key) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(russh::keys::Error::KeyChanged { line }) => {
                return Err(SshError::HostKeyMismatch {
                    host: self.host.clone(),
                    port: self.port,
                    line,
                });
            }
            Err(e) => return Err(SshError::KnownHosts(e)),
        }

        match russh::keys::check_known_hosts_path(
            &self.host,
            self.port,
            server_public_key,
            sloosh_known_hosts_path(),
        ) {
            Ok(true) => Ok(true),
            Ok(false) => Err(SshError::UnknownHostKey {
                host: self.host.clone(),
                port: self.port,
            }),
            Err(russh::keys::Error::KeyChanged { line }) => Err(SshError::HostKeyMismatch {
                host: self.host.clone(),
                port: self.port,
                line,
            }),
            Err(e) => Err(SshError::KnownHosts(e)),
        }
    }

    /// Handle a `-R` forward's incoming connection (docs/internals/architecture.md): only ever
    /// invoked on the one connection a remote forward owns (`route.is_some()`
    /// — every other connection, including `ProxyJump` hops, rejects this
    /// outright rather than accepting a channel nothing will service). Dials
    /// the configured local target *before* accepting, so a refused local
    /// port becomes a clean channel-open failure instead of an accepted
    /// channel nobody pumps bytes through — then hands the accepted channel
    /// and TCP stream off to a spawned task so this callback (invoked
    /// in-line from the connection's own message-processing loop) returns
    /// immediately.
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), SshError> {
        let Some(route) = self.route.clone() else {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        if !route.lifecycle.is_active() {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        if !lease::check_grant(&route.grant).await || !route.lifecycle.is_active() {
            warn!(
                local_host = %route.local_host,
                local_port = route.local_port,
                "remote forward: lease no longer covers this host, refusing forwarded connection"
            );
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        let connect = TcpStream::connect((route.local_host.as_str(), route.local_port));
        match race_forward_target_connect(&route.lifecycle, FORWARD_TARGET_CONNECT_TIMEOUT, connect)
            .await
        {
            Ok(tcp) => {
                if !route.lifecycle.is_active()
                    || !lease::check_grant(&route.grant).await
                    || !route.lifecycle.is_active()
                {
                    reply
                        .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                        .await;
                    return Ok(());
                }

                let lifecycle = route.lifecycle.clone();
                let accept = reply.accept();
                tokio::pin!(accept);
                tokio::select! {
                    biased;
                    _ = lifecycle.wait_closed() => {
                        // Dropping the pending accept future rejects the channel.
                    }
                    _ = &mut accept => {
                        tokio::spawn(pump_forwarded_tcpip(channel, tcp, route));
                    }
                }
            }
            Err(ForwardTargetConnectError::Closed) => {
                reply
                    .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
            }
            Err(ForwardTargetConnectError::TimedOut) => {
                warn!(
                    local_host = %route.local_host, local_port = route.local_port,
                    timeout_secs = FORWARD_TARGET_CONNECT_TIMEOUT.as_secs(),
                    "remote forward: timed out connecting to local target"
                );
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            }
            Err(ForwardTargetConnectError::Io(e)) => {
                warn!(
                    local_host = %route.local_host, local_port = route.local_port, error = %e,
                    "remote forward: local target refused connection"
                );
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            }
        }
        Ok(())
    }
}

/// Pump bytes between a `-R` forward's accepted `forwarded-tcpip` channel and
/// the local TCP target already dialed for it, until either side is done or
/// the owning forward is stopped (docs/internals/architecture.md: a live tunnel dies with its
/// lease, even though it doesn't get a per-byte idle refresh — see
/// `daemon::forward`'s module doc for why per-connection granularity is
/// enough).
async fn pump_forwarded_tcpip(channel: Channel, mut tcp: TcpStream, route: ForwardRoute) {
    route
        .tunnel_count
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut remote = channel.into_stream();
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut tcp, &mut remote) => {}
        _ = route.lifecycle.wait_closed() => {}
    }
    route
        .tunnel_count
        .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
}

/// A `Handler` that accepts whatever host key is presented and just records
/// it, for use by `fetch_host_key` — the approve-flow's out-of-band
/// fingerprint display never wants to fail the connection over an unknown
/// key, since seeing the key *is* the point.
struct KeyCapturingHandler {
    captured: Arc<Mutex<Option<PublicKey>>>,
}

impl russh::client::Handler for KeyCapturingHandler {
    type Error = SshError;

    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool, SshError> {
        let mut guard = self.captured.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(server_public_key.clone());
        Ok(true)
    }
}

/// One host-key confirmation item, ordered so every ProxyJump dependency
/// appears before a target that needs it. Kept crate-private: routed probes
/// are only part of the human `approve` flow while that CLI process has
/// locally unlocked the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostKeyConfirmationTarget {
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    route: HostKeyProbeRoute,
}

/// Result of a read-only routed key probe. The endpoint is returned from the
/// same resolution used for the actual probe, so the CLI records the key
/// against what was really dialed rather than an earlier preview.
pub(crate) struct HostKeyProbeResult {
    pub hostname: String,
    pub port: u16,
    pub key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostKeyProbeRoute {
    hops: Vec<HostConfig>,
    target: HostConfig,
}

/// Whether *any* key is already recorded for `hostname:port` in either
/// known_hosts file, regardless of whether it would actually match a live
/// connection's key. Used by the `sloosh approve` flow (docs/internals/architecture.md) to
/// decide whether a host needs the fetch-fingerprint-confirm dance at all —
/// real verification (which rejects a mismatch outright) still happens in
/// `Handler::check_server_key` at actual connection time.
pub fn host_has_known_key(hostname: &str, port: u16) -> bool {
    let in_ssh = russh::keys::known_hosts::known_host_keys(hostname, port).unwrap_or_default();
    if !in_ssh.is_empty() {
        return true;
    }
    let in_sloosh =
        russh::keys::known_hosts::known_host_keys_path(hostname, port, sloosh_known_hosts_path())
            .unwrap_or_default();
    !in_sloosh.is_empty()
}

/// Dial `hostname:port` far enough to receive its host key (key exchange
/// only — no authentication attempted), for the `sloosh approve` fingerprint
/// display (docs/internals/architecture.md). Used directly by the CLI process, not routed
/// through the daemon: it's a plain read-only network probe with no secrets
/// involved.
pub async fn fetch_host_key(hostname: &str, port: u16) -> Result<PublicKey, SshError> {
    let tcp = open_tcp(hostname, port).await?;
    capture_host_key_over_stream(tcp, hostname, port).await
}

/// Fetch a host key by alias using the same ProxyJump route resolution as a
/// real connection. Intermediate hops use the normal strict known-hosts
/// handler and normal authentication. Only the final target accepts and
/// captures an unknown key, and the probe stops before authenticating to it.
///
/// This deliberately does not enforce daemon leases: it runs in the
/// separate human CLI during `approve`, after that process locally unlocked
/// the vault with the entered master password. Keeping it crate-private
/// prevents it becoming a general-purpose host access path.
pub(crate) async fn fetch_host_key_for_confirmation_target(
    confirmation: &HostKeyConfirmationTarget,
) -> Result<HostKeyProbeResult, SshError> {
    let route = &confirmation.route;
    let hostname = route.target.hostname.clone();
    let port = route.target.port;

    let key = if route.hops.is_empty() {
        let tcp = open_tcp(&hostname, port).await?;
        capture_host_key_over_stream(tcp, &hostname, port).await?
    } else {
        capture_host_key_via_hops(&route.hops, &route.target).await?
    };

    Ok(HostKeyProbeResult {
        hostname,
        port,
        key,
    })
}

async fn capture_host_key_over_stream<S>(
    stream: S,
    hostname: &str,
    port: u16,
) -> Result<PublicKey, SshError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = Arc::new(russh::client::Config::default());
    let captured: Arc<Mutex<Option<PublicKey>>> = Arc::new(Mutex::new(None));
    let handler = KeyCapturingHandler {
        captured: captured.clone(),
    };
    let handle = russh::client::connect_stream(config, stream, handler)
        .await
        .map_err(|e| add_handshake_context(e, hostname, port))?;
    let key = captured
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .ok_or(SshError::Handshake {
            host: hostname.to_string(),
            port,
            source: russh::Error::Disconnect,
        })?;
    drop(handle);
    Ok(key)
}

async fn resolve_host_key_probe_route(
    config: &SshConfig,
    alias: &str,
) -> Result<HostKeyProbeRoute, SshError> {
    let target = resolve_host_config(config, alias).await;
    let mut hops = Vec::new();
    if let Some(jump_spec) = target.proxy_jump.as_deref() {
        let mut seen = HashSet::new();
        seen.insert(target.alias.clone());
        expand_proxy_jump_spec(config, jump_spec, &mut hops, &mut seen).await?;
    }
    Ok(HostKeyProbeRoute { hops, target })
}

async fn capture_host_key_via_hops(
    hops: &[HostConfig],
    target: &HostConfig,
) -> Result<PublicKey, SshError> {
    let mut handles: Vec<russh::client::Handle<Handler>> = Vec::with_capacity(hops.len());
    for (index, hop) in hops.iter().enumerate() {
        let handle = if index == 0 {
            let tcp = open_tcp(&hop.hostname, hop.port).await?;
            connect_over_stream(tcp, hop, None).await?
        } else {
            let previous = handles
                .last()
                .expect("first hop is connected before later hops");
            let channel = previous
                .channel_open_direct_tcpip(hop.hostname.clone(), hop.port as u32, "127.0.0.1", 0)
                .await
                .map_err(|source| SshError::ProxyTunnel {
                    host: hop.hostname.clone(),
                    port: hop.port,
                    source,
                })?;
            connect_over_stream(channel.into_stream(), hop, None).await?
        };
        handles.push(handle);
    }

    let last = handles
        .last()
        .expect("routed key probe calls this helper with at least one hop");
    let channel = last
        .channel_open_direct_tcpip(target.hostname.clone(), target.port as u32, "127.0.0.1", 0)
        .await
        .map_err(|source| SshError::ProxyTunnel {
            host: target.hostname.clone(),
            port: target.port,
            source,
        })?;
    capture_host_key_over_stream(channel.into_stream(), &target.hostname, target.port).await
}

/// Record `key` as the trusted host key for `hostname:port` in sloosh's own
/// known_hosts file (`~/.sloosh/known_hosts`, mode 0600), called after the
/// human confirms the fingerprint during `sloosh approve` (docs/internals/architecture.md).
pub fn record_sloosh_known_host(
    hostname: &str,
    port: u16,
    key: &PublicKey,
) -> Result<(), SshError> {
    let path = sloosh_known_hosts_path();
    russh::keys::known_hosts::learn_known_hosts_path(hostname, port, key, &path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| SshError::KnownHosts(russh::keys::Error::IO(e)))?;
    Ok(())
}

/// Resolve `alias` to the endpoint an actual connection would dial, with
/// the same precedence as `connect` (vault entry — only visible while the
/// vault is unlocked — then `~/.ssh/config`, then the alias as a literal
/// hostname). Used daemon-side during `approve` to tell the CLI which
/// endpoints still need a host-key fingerprint confirmation; the endpoint
/// itself is not a secret.
pub async fn resolve_endpoint(alias: &str) -> (String, u16) {
    let config = SshConfig::load_default();
    let host_cfg = resolve_host_config(&config, alias).await;
    (host_cfg.hostname, host_cfg.port)
}

/// Connect to `alias`, resolving it through `~/.ssh/config`, dialing the full
/// `ProxyJump` chain if configured (checking a lease for each vault-backed
/// hop along the way), verifying the host key, and authenticating via
/// ssh-agent then unencrypted `IdentityFile` keys.
/// `lease_ctx` identifies the caller a lease for the *target* host has
/// already been confirmed for one layer up (`daemon/mod.rs`); it's reused
/// here only to check jump hops, never the target itself.
pub async fn connect(alias: &str, lease_ctx: &LeaseContext) -> Result<Connection, SshError> {
    connect_with_route(alias, lease_ctx, None).await
}

/// Same as [`connect`], but for a `-R` remote-forward connection
/// (`daemon::forward`): `route`, if given, is attached to the *target*
/// host's [`Handler`] only (never an intermediate `ProxyJump` hop's), so
/// `server_channel_open_forwarded_tcpip` can route the target's
/// `forwarded-tcpip` channels to the forward's local destination.
pub(crate) async fn connect_with_route(
    alias: &str,
    lease_ctx: &LeaseContext,
    route: Option<ForwardRoute>,
) -> Result<Connection, SshError> {
    let config = SshConfig::load_default();
    let host_cfg = resolve_host_config(&config, alias).await;
    connect_resolved(&config, host_cfg, lease_ctx, route).await
}

/// Resolve `alias`, preferring a vault entry over `~/.ssh/config`. Only ever
/// finds a vault
/// entry while the vault's derived key is cached (i.e. at least one lease is
/// active) — `vault::get_entry` returns `None` otherwise, so this quietly
/// falls back to the plain config-file resolution, exactly like an alias
/// that was never in the vault at all.
async fn resolve_host_config(config: &SshConfig, alias: &str) -> HostConfig {
    if let Some(entry) = vault::get_entry(alias).await {
        return HostConfig {
            alias: alias.to_string(),
            hostname: entry.hostname,
            port: entry.port.unwrap_or(22),
            user: entry.user.unwrap_or_else(current_user),
            // Vault entries don't carry key-based identities (docs/internals/architecture.md
            // only specifies password auth for vault entries); a
            // vault-backed host that also needs one of those should keep
            // using ~/.ssh/config instead.
            identity_files: Vec::new(),
            proxy_jump: entry.jump,
            identity_agent: None,
        };
    }
    config.resolve(alias)
}

async fn connect_resolved(
    config: &SshConfig,
    host_cfg: HostConfig,
    lease_ctx: &LeaseContext,
    route: Option<ForwardRoute>,
) -> Result<Connection, SshError> {
    if let Some(jump_spec) = host_cfg.proxy_jump.clone() {
        return connect_via_proxy_jump(config, &jump_spec, host_cfg, lease_ctx, route).await;
    }

    let tcp = open_tcp(&host_cfg.hostname, host_cfg.port).await?;
    let handle = connect_over_stream(tcp, &host_cfg, route).await?;
    Ok(Connection {
        handle,
        resolved: host_cfg,
        _jumps: Vec::new(),
    })
}

/// Dial the full `ProxyJump` chain for `target_cfg`, then the target itself.
/// The chain is resolved up front (`expand_proxy_jump_spec`) so depth-cap and
/// cycle errors surface before any network activity, then dialed hop by hop:
/// TCP to the first hop, every later hop (and finally the target) over a
/// `direct-tcpip` channel opened on the previous hop's connection. Every
/// vault-backed hop must have its own active lease (docs/internals/architecture.md) — checked
/// right before dialing it, via `ensure_hop_leased`.
async fn connect_via_proxy_jump(
    config: &SshConfig,
    jump_spec: &str,
    target_cfg: HostConfig,
    lease_ctx: &LeaseContext,
    route: Option<ForwardRoute>,
) -> Result<Connection, SshError> {
    let mut seen = HashSet::new();
    seen.insert(target_cfg.alias.clone());
    let mut chain = Vec::new();
    expand_proxy_jump_spec(config, jump_spec, &mut chain, &mut seen).await?;

    if chain.is_empty() {
        // Every hop the spec named resolved to the target itself or was
        // otherwise elided — fall back to a direct connection rather than
        // erroring on what amounts to a no-op ProxyJump.
        let tcp = open_tcp(&target_cfg.hostname, target_cfg.port).await?;
        let handle = connect_over_stream(tcp, &target_cfg, route).await?;
        return Ok(Connection {
            handle,
            resolved: target_cfg,
            _jumps: Vec::new(),
        });
    }

    let mut handles: Vec<russh::client::Handle<Handler>> = Vec::with_capacity(chain.len());
    for (i, hop_cfg) in chain.iter().enumerate() {
        ensure_hop_leased(hop_cfg, &target_cfg.alias, lease_ctx).await?;
        if i == 0 {
            let tcp = open_tcp(&hop_cfg.hostname, hop_cfg.port).await?;
            // Intermediate hops never route forwarded-tcpip channels: only
            // the final target's `Handler` gets `route`.
            let handle = connect_over_stream(tcp, hop_cfg, None).await?;
            handles.push(handle);
        } else {
            let prev = handles
                .last()
                .expect("first hop pushed before this branch runs");
            let channel = prev
                .channel_open_direct_tcpip(
                    hop_cfg.hostname.clone(),
                    hop_cfg.port as u32,
                    "127.0.0.1",
                    0,
                )
                .await
                .map_err(|source| SshError::ProxyTunnel {
                    host: hop_cfg.hostname.clone(),
                    port: hop_cfg.port,
                    source,
                })?;
            let stream = channel.into_stream();
            let handle = connect_over_stream(stream, hop_cfg, None).await?;
            handles.push(handle);
        }
    }

    let last = handles.last().expect("chain is non-empty in this branch");
    let channel = last
        .channel_open_direct_tcpip(
            target_cfg.hostname.clone(),
            target_cfg.port as u32,
            "127.0.0.1",
            0,
        )
        .await
        .map_err(|source| SshError::ProxyTunnel {
            host: target_cfg.hostname.clone(),
            port: target_cfg.port,
            source,
        })?;
    let stream = channel.into_stream();
    let handle = connect_over_stream(stream, &target_cfg, route).await?;

    Ok(Connection {
        handle,
        resolved: target_cfg,
        _jumps: handles,
    })
}

/// Recursively expand a `ProxyJump` spec (comma-separated hops, OpenSSH
/// semantics: the first entry is connected to first) into a flat, dial-ordered
/// chain of resolved hop configs. Each hop's own `ProxyJump` (vault `jump`
/// field or `~/.ssh/config` directive) is expanded too, and its hops are
/// inserted *before* the hop that depends on them, since they must be reached
/// first. `seen` starts out containing the ultimate target's alias so a chain
/// that loops back to the target is also caught. Enforces
/// [`MAX_PROXY_JUMP_HOPS`] and rejects revisiting any alias already in `seen`.
async fn expand_proxy_jump_spec(
    config: &SshConfig,
    spec: &str,
    chain: &mut Vec<HostConfig>,
    seen: &mut HashSet<String>,
) -> Result<(), SshError> {
    for entry in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let alias = parse_proxy_jump_alias(entry).to_string();
        if chain.len() >= MAX_PROXY_JUMP_HOPS {
            return Err(SshError::ProxyJumpTooDeep {
                limit: MAX_PROXY_JUMP_HOPS,
            });
        }
        if !seen.insert(alias.clone()) {
            return Err(SshError::ProxyJumpCycle { alias });
        }

        let mut hop_cfg = resolve_host_config(config, &alias).await;
        apply_proxy_jump_overrides(entry, &mut hop_cfg);
        let nested_jump = hop_cfg.proxy_jump.take();

        if let Some(nested_spec) = nested_jump {
            Box::pin(expand_proxy_jump_spec(config, &nested_spec, chain, seen)).await?;
        }
        chain.push(hop_cfg);
    }
    Ok(())
}

/// Enforce docs/internals/architecture.md's chain lease invariant for a single hop: if `hop`'s
/// credentials come from the vault, the requesting process needs its own
/// active lease for it, same as the target host gets one layer up. A hop
/// resolved purely from `~/.ssh/config` uses ambient user credentials and
/// needs no lease.
async fn ensure_hop_leased(
    hop_cfg: &HostConfig,
    target: &str,
    lease_ctx: &LeaseContext,
) -> Result<(), SshError> {
    if vault::get_entry(&hop_cfg.alias).await.is_none() {
        return Ok(());
    }
    let authorized = lease::check_authorized(
        lease_ctx.caller_pid,
        &hop_cfg.alias,
        lease_ctx.lease_token.as_deref(),
    )
    .await;
    if authorized {
        Ok(())
    } else {
        Err(SshError::JumpHostLeaseRequired {
            hop: hop_cfg.alias.clone(),
            target: target.to_string(),
        })
    }
}

/// Expand `hosts` (as requested via `Request::RequestLease`) to also include
/// every alias in each host's `ProxyJump` chain (docs/internals/architecture.md), so the human
/// approving the request sees — and grants — coverage for the whole path,
/// not just the final target. Order is preserved: each requested host first,
/// then its jump hops, deduplicated overall. Resolution failures for a given
/// host's chain (e.g. a cycle) are logged and skipped rather than failing
/// the whole request — `RequestLease` should never become unusable because
/// of a misconfigured jump host the caller didn't even ask to touch directly.
pub async fn expand_lease_hosts(hosts: &[String]) -> Vec<String> {
    let config = SshConfig::load_default();
    let mut seen = HashSet::new();
    let mut expanded = Vec::new();

    for host in hosts {
        if seen.insert(host.clone()) {
            expanded.push(host.clone());
        }
    }
    for host in hosts {
        match jump_chain_aliases(&config, host).await {
            Ok(aliases) => {
                for alias in aliases {
                    if seen.insert(alias.clone()) {
                        expanded.push(alias);
                    }
                }
            }
            Err(e) => {
                warn!(host, error = %e, "could not expand ProxyJump chain for lease request; \
                       requesting only the host itself");
            }
        }
    }
    expanded
}

/// Build host-key confirmation work in dependency order: every target's
/// ProxyJump chain first (dial order), then the target, deduplicated across
/// all granted hosts. This lets the human record a bastion before a later
/// target probe must strictly verify and authenticate through that bastion.
pub(crate) async fn host_key_confirmation_order(
    hosts: &[String],
) -> Vec<HostKeyConfirmationTarget> {
    let config = SshConfig::load_default();
    host_key_confirmation_order_with_config(&config, hosts).await
}

async fn host_key_confirmation_order_with_config(
    config: &SshConfig,
    hosts: &[String],
) -> Vec<HostKeyConfirmationTarget> {
    let mut dependency_groups = Vec::with_capacity(hosts.len());
    let mut routes: Vec<(String, HostKeyProbeRoute)> = Vec::new();
    for host in hosts {
        let route = match resolve_host_key_probe_route(config, host).await {
            Ok(route) => route,
            Err(e) => {
                warn!(host, error = %e, "could not plan ProxyJump host-key confirmation route; \
                       skipping the probe rather than bypassing the configured route");
                continue;
            }
        };
        let dependencies: Vec<String> = route.hops.iter().map(|hop| hop.alias.clone()).collect();
        for (index, hop) in route.hops.iter().enumerate() {
            if !routes.iter().any(|(alias, _)| alias == &hop.alias) {
                routes.push((
                    hop.alias.clone(),
                    HostKeyProbeRoute {
                        hops: route.hops[..index].to_vec(),
                        target: hop.clone(),
                    },
                ));
            }
        }
        if !routes.iter().any(|(alias, _)| alias == host) {
            routes.push((host.clone(), route));
        }
        dependency_groups.push((host.clone(), dependencies));
    }

    let aliases = dependency_first_aliases(&dependency_groups);
    let mut targets = Vec::with_capacity(aliases.len());
    for alias in aliases {
        let route = routes
            .iter()
            .find(|(candidate, _)| candidate == &alias)
            .map(|(_, route)| route.clone())
            .expect("every ordered alias has a planned probe route");
        targets.push(HostKeyConfirmationTarget {
            alias,
            hostname: route.target.hostname.clone(),
            port: route.target.port,
            route,
        });
    }
    targets
}

fn dependency_first_aliases(groups: &[(String, Vec<String>)]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut ordered = Vec::new();
    for (target, dependencies) in groups {
        for alias in dependencies.iter().chain(std::iter::once(target)) {
            if seen.insert(alias.clone()) {
                ordered.push(alias.clone());
            }
        }
    }
    ordered
}

/// The alias chain of `alias`'s `ProxyJump` (if any), in dial order — reuses
/// `expand_proxy_jump_spec` so lease-request-time expansion and
/// connect-time dialing agree on exactly what "the chain" means.
async fn jump_chain_aliases(config: &SshConfig, alias: &str) -> Result<Vec<String>, SshError> {
    let host_cfg = resolve_host_config(config, alias).await;
    let Some(jump_spec) = host_cfg.proxy_jump else {
        return Ok(Vec::new());
    };
    let mut seen = HashSet::new();
    seen.insert(alias.to_string());
    let mut chain = Vec::new();
    expand_proxy_jump_spec(config, &jump_spec, &mut chain, &mut seen).await?;
    Ok(chain.into_iter().map(|c| c.alias).collect())
}

/// `user@host:port` (all but the host part optional) as accepted by
/// OpenSSH's `ProxyJump`.
fn parse_proxy_jump_alias(spec: &str) -> &str {
    let after_user = spec.rsplit_once('@').map(|(_, h)| h).unwrap_or(spec);
    after_user
        .split_once(':')
        .map(|(h, _)| h)
        .unwrap_or(after_user)
}

fn apply_proxy_jump_overrides(spec: &str, cfg: &mut HostConfig) {
    let (user_part, host_part) = spec
        .rsplit_once('@')
        .map(|(u, h)| (Some(u), h))
        .unwrap_or((None, spec));
    if let Some(user) = user_part {
        cfg.user = user.to_string();
    }
    if let Some((_, port_str)) = host_part.split_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            cfg.port = port;
        }
    }
}

/// Resolve `host` and open a TCP connection, trying every resolved address
/// (v4 and v6) like real `ssh` does. Failures are classified so the
/// agent-facing message says what actually went wrong: DNS vs refused vs
/// timeout vs anything else (docs/internals/architecture.md — errors are teaching material).
async fn open_tcp(host: &str, port: u16) -> Result<TcpStream, SshError> {
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|source| SshError::HostResolution {
            host: host.to_string(),
            source,
        })?
        .collect();
    if addrs.is_empty() {
        return Err(SshError::HostResolution {
            host: host.to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "hostname resolved to no addresses",
            ),
        });
    }
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    // `addrs` is non-empty, so at least one attempt ran and failed.
    Err(classify_connect_error(host, port, last_err.unwrap()))
}

fn classify_connect_error(host: &str, port: u16, source: std::io::Error) -> SshError {
    let host = host.to_string();
    match source.kind() {
        std::io::ErrorKind::ConnectionRefused => SshError::ConnectRefused { host, port, source },
        std::io::ErrorKind::TimedOut => SshError::ConnectTimeout { host, port, source },
        _ => SshError::Connect { host, port, source },
    }
}

/// Handshake-stage failures come out of `russh` as bare protocol errors
/// with no endpoint attached (e.g. `Disconnected` when the peer closes the
/// socket mid-negotiation). Wrap them so the agent-facing message names the
/// host and suggests a next step; errors that already carry their own
/// self-teaching context (host-key verdicts, auth) pass through untouched.
fn add_handshake_context(err: SshError, host: &str, port: u16) -> SshError {
    match err {
        SshError::Russh(source) => SshError::Handshake {
            host: host.to_string(),
            port,
            source,
        },
        other => other,
    }
}

async fn connect_over_stream<S>(
    stream: S,
    host_cfg: &HostConfig,
    route: Option<ForwardRoute>,
) -> Result<russh::client::Handle<Handler>, SshError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = Arc::new(russh::client::Config::default());
    let handler = Handler {
        host: host_cfg.hostname.clone(),
        port: host_cfg.port,
        route,
    };
    let mut handle = russh::client::connect_stream(config, stream, handler)
        .await
        .map_err(|e| add_handshake_context(e, &host_cfg.hostname, host_cfg.port))?;
    authenticate(&mut handle, host_cfg).await?;
    Ok(handle)
}

/// Auth order: ssh-agent identities first, then unencrypted `IdentityFile`
/// keys, then a vault-stored password (only
/// available while the vault is unlocked, i.e. while a lease is active).
async fn authenticate(
    handle: &mut russh::client::Handle<Handler>,
    host_cfg: &HostConfig,
) -> Result<(), SshError> {
    let hash_alg = handle
        .best_supported_rsa_hash()
        .await
        .ok()
        .flatten()
        .flatten();

    if try_agent_auth(handle, host_cfg, hash_alg).await? {
        return Ok(());
    }

    let mut encrypted_identities = Vec::new();
    for path in &host_cfg.identity_files {
        match russh::keys::load_secret_key(path, None) {
            Ok(key) => {
                let key = Arc::new(key);
                let with_hash = PrivateKeyWithHashAlg::new(key, hash_alg);
                match handle
                    .authenticate_publickey(&host_cfg.user, with_hash)
                    .await
                {
                    Ok(res) if res.success() => return Ok(()),
                    Ok(_) => debug!(path = %path.display(), "identity file rejected by server"),
                    Err(e) => {
                        debug!(path = %path.display(), error = %e, "identity file auth error")
                    }
                }
            }
            Err(russh::keys::Error::KeyIsEncrypted) => {
                encrypted_identities.push(path.clone());
            }
            Err(e) => {
                debug!(path = %path.display(), error = %e, "could not load identity file, skipping");
            }
        }
    }

    // Vault password auth (docs/internals/architecture.md): only ever finds an entry while
    // the vault's derived key is cached, i.e. while at least one lease is
    // active — the credential never comes from a CLI argument or the
    // agent's context, only from the daemon's in-memory unlocked vault.
    if let Some(entry) = vault::get_entry(&host_cfg.alias).await {
        let vault::AuthMethod::Password { password } = entry.auth;
        let mut password = password;
        let result = handle
            .authenticate_password(&host_cfg.user, password.clone())
            .await;
        // We can zeroize our own copy; the copy `russh` moved onto its
        // internal message channel is out of our control (the crate's
        // `authenticate_password` takes the password by value, not by
        // reference) — noted as a known limitation, not a full guarantee.
        password.zeroize();
        match result {
            Ok(res) if res.success() => return Ok(()),
            Ok(_) => debug!(alias = %host_cfg.alias, "vault password rejected by server"),
            Err(e) => debug!(alias = %host_cfg.alias, error = %e, "vault password auth error"),
        }
    }

    if let Some(path) = encrypted_identities.into_iter().next() {
        return Err(SshError::EncryptedIdentity { path });
    }
    Err(SshError::AuthFailed {
        host: host_cfg.alias.clone(),
    })
}

/// Try every identity ssh-agent offers. Returns `Ok(true)` on success,
/// `Ok(false)` if the agent is unreachable/empty or rejected everything
/// (not a hard error — docs/internals/architecture.md says agent auth is tried first, not
/// that it's required), and `Err` only for a genuine signing failure that
/// should stop the auth attempt. Connects to the host's `IdentityAgent`
/// socket if configured (`none` disables agent auth for the host entirely),
/// otherwise falls back to the default `$SSH_AUTH_SOCK` agent.
async fn try_agent_auth(
    handle: &mut russh::client::Handle<Handler>,
    host_cfg: &HostConfig,
    hash_alg: Option<HashAlg>,
) -> Result<bool, SshError> {
    let mut agent = match &host_cfg.identity_agent {
        Some(IdentityAgentValue::Disabled) => return Ok(false),
        Some(IdentityAgentValue::Path(path)) => {
            match russh::keys::agent::client::AgentClient::connect_uds(path).await {
                Ok(agent) => agent,
                Err(_) => return Ok(false),
            }
        }
        None => match russh::keys::agent::client::AgentClient::connect_env().await {
            Ok(agent) => agent,
            Err(_) => return Ok(false),
        },
    };
    let Ok(identities) = agent.request_identities().await else {
        return Ok(false);
    };
    for identity in identities {
        let russh::keys::agent::AgentIdentity::PublicKey { key, comment } = identity else {
            // Certificate identities aren't wired up in this milestone.
            continue;
        };
        match handle
            .authenticate_publickey_with(&host_cfg.user, key, hash_alg, &mut agent)
            .await
        {
            Ok(res) if res.success() => return Ok(true),
            Ok(_) => debug!(comment, "ssh-agent identity rejected by server"),
            Err(e) => debug!(comment, error = ?e, "ssh-agent signing error"),
        }
    }
    Ok(false)
}

/// Terminal modes requested for every session PTY: echo off (docs/internals/architecture.md
/// "抑制回显" — primary mechanism; `session.rs` also defensively strips a
/// leading echoed command line in case a server ignores this).
pub fn quiet_pty_modes() -> Vec<(Pty, u32)> {
    vec![(Pty::ECHO, 0), (Pty::ECHONL, 0)]
}

/// Re-exported so `session.rs` doesn't need its own `russh` import purely
/// for this one type used at the ssh<->session boundary.
pub type Channel = russh::Channel<russh::client::Msg>;
pub type ChannelReadHalf = russh::ChannelReadHalf;
pub type ChannelWriteHalf = russh::ChannelWriteHalf<russh::client::Msg>;

pub use russh::ChannelMsg as SessionChannelMsg;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_forward_route_lifecycle_is_monotonic() {
        let lifecycle = ForwardRouteLifecycle::new();
        assert_eq!(lifecycle.state(), ForwardRouteState::Pending);
        assert!(!lifecycle.is_active());

        assert!(lifecycle.activate());
        assert_eq!(lifecycle.state(), ForwardRouteState::Active);
        assert!(lifecycle.is_active());

        assert!(lifecycle.close());
        assert_eq!(lifecycle.state(), ForwardRouteState::Closed);
        assert!(!lifecycle.is_active());
        assert!(!lifecycle.activate(), "closed routes must never reopen");
        assert_eq!(lifecycle.state(), ForwardRouteState::Closed);
    }

    #[tokio::test]
    async fn remote_forward_route_close_wakes_waiters() {
        let lifecycle = ForwardRouteLifecycle::new();
        let waiter = lifecycle.clone();
        let task = tokio::spawn(async move { waiter.wait_closed().await });

        tokio::task::yield_now().await;
        assert!(lifecycle.close());
        tokio::time::timeout(std::time::Duration::from_millis(100), task)
            .await
            .expect("closing route should wake waiters")
            .expect("waiter task should complete");
    }

    #[tokio::test]
    async fn remote_forward_local_connect_races_close_and_timeout() {
        let lifecycle = ForwardRouteLifecycle::new();
        assert!(lifecycle.activate());
        let closing_lifecycle = lifecycle.clone();
        let task = tokio::spawn(async move {
            race_forward_target_connect(
                &closing_lifecycle,
                std::time::Duration::from_secs(30),
                std::future::pending::<std::io::Result<()>>(),
            )
            .await
        });
        tokio::task::yield_now().await;
        lifecycle.close();
        assert!(matches!(
            task.await.expect("connect race task should complete"),
            Err(ForwardTargetConnectError::Closed)
        ));

        let lifecycle = ForwardRouteLifecycle::new();
        assert!(lifecycle.activate());
        let result = race_forward_target_connect(
            &lifecycle,
            std::time::Duration::from_millis(1),
            std::future::pending::<std::io::Result<()>>(),
        )
        .await;
        assert!(matches!(result, Err(ForwardTargetConnectError::TimedOut)));
    }

    #[test]
    fn glob_matches_star_and_question_mark() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("web*", "web01"));
        assert!(glob_match("web?", "web1"));
        assert!(!glob_match("web?", "web12"));
        assert!(!glob_match("web*", "db01"));
        assert!(glob_match("192.168.*.*", "192.168.1.5"));
    }

    #[test]
    fn host_block_pattern_supports_negation() {
        let patterns = vec!["*".to_string(), "!bastion".to_string()];
        assert!(host_patterns_match(&patterns, "web01"));
        assert!(!host_patterns_match(&patterns, "bastion"));
    }

    #[test]
    fn parses_hostname_port_user_identityfile() {
        let contents = "\
Host myhost
    HostName 10.0.0.5
    Port 2222
    User deploy
    IdentityFile ~/.ssh/id_ed25519
";
        let cfg = SshConfig::parse(contents);
        let resolved = cfg.resolve("myhost");
        assert_eq!(resolved.hostname, "10.0.0.5");
        assert_eq!(resolved.port, 2222);
        assert_eq!(resolved.user, "deploy");
        assert_eq!(resolved.identity_files.len(), 1);
        assert!(resolved.identity_files[0].ends_with(".ssh/id_ed25519"));
    }

    #[test]
    fn glob_pattern_in_host_line_matches_alias() {
        let contents = "\
Host web*
    User www-data
";
        let cfg = SshConfig::parse(contents);
        let resolved = cfg.resolve("web03");
        assert_eq!(resolved.user, "www-data");
        // Doesn't match, falls back to defaults (literal hostname == alias).
        let other = cfg.resolve("db01");
        assert_eq!(other.hostname, "db01");
        assert_ne!(other.user, "www-data");
    }

    #[test]
    fn unresolved_host_defaults_to_literal_hostname_and_port_22() {
        let cfg = SshConfig::parse("");
        let resolved = cfg.resolve("plain.example.com");
        assert_eq!(resolved.hostname, "plain.example.com");
        assert_eq!(resolved.port, 22);
    }

    #[test]
    fn user_at_host_literal_splits_like_an_openssh_destination() {
        let cfg = SshConfig::parse("");
        let resolved = cfg.resolve("deploy@10.0.0.7");
        assert_eq!(resolved.alias, "deploy@10.0.0.7");
        assert_eq!(resolved.hostname, "10.0.0.7");
        assert_eq!(resolved.user, "deploy");
        assert_eq!(resolved.port, 22);
    }

    #[test]
    fn user_at_host_literal_matches_config_blocks_by_host_and_wins_on_user() {
        let contents = "\
Host 10.0.0.7
    Port 2222
    User ignored-by-explicit-user
";
        let cfg = SshConfig::parse(contents);
        let resolved = cfg.resolve("deploy@10.0.0.7");
        assert_eq!(resolved.hostname, "10.0.0.7");
        assert_eq!(resolved.port, 2222);
        assert_eq!(resolved.user, "deploy");
    }

    #[test]
    fn first_matching_block_wins_like_real_ssh_config() {
        let contents = "\
Host myhost
    User first

Host *
    User second
";
        let cfg = SshConfig::parse(contents);
        let resolved = cfg.resolve("myhost");
        assert_eq!(resolved.user, "first");
    }

    #[test]
    fn unknown_directive_does_not_panic_and_parsing_continues() {
        let contents = "\
Host myhost
    ForwardAgent yes
    User deploy
";
        let cfg = SshConfig::parse(contents);
        let resolved = cfg.resolve("myhost");
        // The unknown directive was skipped (and warned about), but parsing
        // kept going and picked up the directive after it.
        assert_eq!(resolved.user, "deploy");
    }

    #[test]
    fn proxy_jump_directive_is_captured() {
        let contents = "\
Host inner
    HostName 10.0.0.9
    ProxyJump jump@bastion.example.com:2200
";
        let cfg = SshConfig::parse(contents);
        let resolved = cfg.resolve("inner");
        assert_eq!(
            resolved.proxy_jump.as_deref(),
            Some("jump@bastion.example.com:2200")
        );
    }

    #[test]
    fn proxy_jump_chain_directive_is_captured_verbatim() {
        let contents = "Host inner\n    ProxyJump hop1,hop2\n";
        let cfg = SshConfig::parse(contents);
        let resolved = cfg.resolve("inner");
        assert_eq!(resolved.proxy_jump.as_deref(), Some("hop1,hop2"));
        // Expansion into a dial-ordered chain happens in
        // expand_proxy_jump_spec, exercised by the tests below.
    }

    #[test]
    fn parse_proxy_jump_alias_strips_user_and_port() {
        assert_eq!(parse_proxy_jump_alias("bastion"), "bastion");
        assert_eq!(parse_proxy_jump_alias("user@bastion"), "bastion");
        assert_eq!(parse_proxy_jump_alias("user@bastion:2200"), "bastion");
    }

    #[tokio::test]
    async fn expand_proxy_jump_spec_splits_comma_chain_in_order() {
        let config = SshConfig::default();
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        seen.insert("target".to_string());
        expand_proxy_jump_spec(&config, "hop1,hop2", &mut chain, &mut seen)
            .await
            .unwrap();
        let aliases: Vec<&str> = chain.iter().map(|c| c.alias.as_str()).collect();
        assert_eq!(aliases, vec!["hop1", "hop2"]);
    }

    #[tokio::test]
    async fn expand_proxy_jump_spec_recurses_into_nested_jump_before_the_hop() {
        let contents = "\
Host hop2
    ProxyJump hop1
";
        let config = SshConfig::parse(contents);
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        seen.insert("target".to_string());
        expand_proxy_jump_spec(&config, "hop2", &mut chain, &mut seen)
            .await
            .unwrap();
        // hop1 (hop2's own jump host) must be dialed before hop2.
        let aliases: Vec<&str> = chain.iter().map(|c| c.alias.as_str()).collect();
        assert_eq!(aliases, vec!["hop1", "hop2"]);
    }

    #[test]
    fn host_key_dependencies_are_ordered_before_targets_and_deduplicated() {
        let groups = vec![
            (
                "nas".to_string(),
                vec!["edge".to_string(), "bastion".to_string()],
            ),
            ("db".to_string(), vec!["edge".to_string()]),
            ("bastion".to_string(), vec!["edge".to_string()]),
            ("nas".to_string(), Vec::new()),
        ];

        assert_eq!(
            dependency_first_aliases(&groups),
            vec!["edge", "bastion", "nas", "db"]
        );
    }

    #[tokio::test]
    async fn host_key_confirmation_plan_uses_nested_proxy_route_without_network() {
        let config = SshConfig::parse(
            "\
Host sloosh-probe-target
    HostName 10.0.0.30
    ProxyJump sloosh-probe-hop2
Host sloosh-probe-hop2
    HostName 10.0.0.20
    ProxyJump sloosh-probe-hop1
Host sloosh-probe-hop1
    HostName 10.0.0.10
Host sloosh-probe-other
    HostName 10.0.0.40
    ProxyJump sloosh-probe-hop1
",
        );
        let hosts = vec![
            "sloosh-probe-target".to_string(),
            "sloosh-probe-other".to_string(),
            "sloosh-probe-hop2".to_string(),
        ];

        let plan = host_key_confirmation_order_with_config(&config, &hosts).await;
        let aliases: Vec<&str> = plan.iter().map(|target| target.alias.as_str()).collect();
        assert_eq!(
            aliases,
            vec![
                "sloosh-probe-hop1",
                "sloosh-probe-hop2",
                "sloosh-probe-target",
                "sloosh-probe-other",
            ]
        );
        assert_eq!(plan[0].hostname, "10.0.0.10");
        assert_eq!(plan[1].hostname, "10.0.0.20");
        assert_eq!(plan[2].hostname, "10.0.0.30");
        assert_eq!(plan[3].hostname, "10.0.0.40");
    }

    #[tokio::test]
    async fn host_key_confirmation_never_falls_back_to_direct_on_bad_route() {
        let config = SshConfig::parse(
            "\
Host sloosh-probe-cycle-a
    HostName 10.0.0.10
    ProxyJump sloosh-probe-cycle-b
Host sloosh-probe-cycle-b
    HostName 10.0.0.20
    ProxyJump sloosh-probe-cycle-a
",
        );
        let plan =
            host_key_confirmation_order_with_config(&config, &["sloosh-probe-cycle-a".to_string()])
                .await;
        assert!(plan.is_empty());
    }

    #[tokio::test]
    async fn expand_proxy_jump_spec_rejects_chains_deeper_than_the_cap() {
        let config = SshConfig::default();
        let long_spec: Vec<String> = (0..MAX_PROXY_JUMP_HOPS + 1)
            .map(|i| format!("hop{i}"))
            .collect();
        let spec = long_spec.join(",");
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        seen.insert("target".to_string());
        let err = expand_proxy_jump_spec(&config, &spec, &mut chain, &mut seen)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SshError::ProxyJumpTooDeep { limit } if limit == MAX_PROXY_JUMP_HOPS)
        );
    }

    #[tokio::test]
    async fn expand_proxy_jump_spec_detects_direct_cycle() {
        let contents = "\
Host hopA
    ProxyJump hopB
Host hopB
    ProxyJump hopA
";
        let config = SshConfig::parse(contents);
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        seen.insert("target".to_string());
        let err = expand_proxy_jump_spec(&config, "hopA", &mut chain, &mut seen)
            .await
            .unwrap_err();
        assert!(matches!(err, SshError::ProxyJumpCycle { alias } if alias == "hopA"));
    }

    #[tokio::test]
    async fn expand_proxy_jump_spec_detects_cycle_back_to_target() {
        let contents = "\
Host bastion
    ProxyJump target
";
        let config = SshConfig::parse(contents);
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        seen.insert("target".to_string());
        let err = expand_proxy_jump_spec(&config, "bastion", &mut chain, &mut seen)
            .await
            .unwrap_err();
        assert!(matches!(err, SshError::ProxyJumpCycle { alias } if alias == "target"));
    }

    #[test]
    fn identity_agent_directive_parses_path_and_expands_tilde() {
        let contents = "\
Host myhost
    IdentityAgent ~/.1password/agent.sock
";
        let cfg = SshConfig::parse(contents);
        let resolved = cfg.resolve("myhost");
        match resolved.identity_agent {
            Some(IdentityAgentValue::Path(p)) => {
                assert!(p.ends_with(".1password/agent.sock"), "{p:?}");
            }
            other => panic!("expected Path variant, got {other:?}"),
        }
    }

    #[test]
    fn identity_agent_none_disables_agent_auth() {
        let contents = "\
Host myhost
    IdentityAgent none
";
        let cfg = SshConfig::parse(contents);
        let resolved = cfg.resolve("myhost");
        assert_eq!(resolved.identity_agent, Some(IdentityAgentValue::Disabled));
    }

    #[test]
    fn identity_agent_accepts_quoted_path() {
        let contents = "\
Host myhost
    IdentityAgent \"/tmp/some agent.sock\"
";
        let cfg = SshConfig::parse(contents);
        let resolved = cfg.resolve("myhost");
        assert_eq!(
            resolved.identity_agent,
            Some(IdentityAgentValue::Path(PathBuf::from(
                "/tmp/some agent.sock"
            )))
        );
    }

    // -- error Display formatting: every agent-facing message must say what
    //    failed AND what to do next, with the raw error only as detail
    //    (docs/internals/architecture.md). -----------------------------------------------------

    #[test]
    fn dns_error_names_host_and_suggests_config_fix() {
        let err = SshError::HostResolution {
            host: "nonexistent-host-xyz".to_string(),
            source: std::io::Error::other("nodename nor servname provided"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("could not resolve host 'nonexistent-host-xyz'"),
            "{msg}"
        );
        assert!(msg.contains("~/.ssh/config"), "{msg}");
        // Underlying detail preserved, but not the whole message.
        assert!(msg.contains("nodename nor servname provided"), "{msg}");
    }

    #[test]
    fn classify_connect_error_maps_refused_and_timeout() {
        let refused = classify_connect_error(
            "web01",
            2222,
            std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
        );
        let msg = refused.to_string();
        assert!(msg.contains("web01:2222"), "{msg}");
        assert!(msg.contains("refused"), "{msg}");
        assert!(msg.contains("sshd"), "{msg}");

        let timeout = classify_connect_error(
            "web01",
            22,
            std::io::Error::from(std::io::ErrorKind::TimedOut),
        );
        let msg = timeout.to_string();
        assert!(msg.contains("timed out connecting to web01:22"), "{msg}");
        assert!(msg.contains("ssh web01"), "{msg}");

        let other = classify_connect_error(
            "web01",
            22,
            std::io::Error::from(std::io::ErrorKind::NetworkUnreachable),
        );
        let msg = other.to_string();
        assert!(msg.contains("failed to connect to web01:22"), "{msg}");
        assert!(msg.contains("firewall"), "{msg}");
    }

    #[test]
    fn handshake_context_wraps_bare_russh_errors_only() {
        let wrapped = add_handshake_context(
            SshError::Russh(russh::Error::Disconnect),
            "nonexistent-host-xyz",
            22,
        );
        let msg = wrapped.to_string();
        assert!(
            msg.contains("SSH handshake with nonexistent-host-xyz:22 failed"),
            "{msg}"
        );
        assert!(msg.contains("may not be an SSH server"), "{msg}");
        // Raw russh error kept as parenthetical detail, not the whole story.
        assert!(msg.contains("russh:"), "{msg}");
        assert!(msg.contains("Disconnected"), "{msg}");

        // A variant that already carries context must pass through unchanged.
        let unknown = add_handshake_context(
            SshError::UnknownHostKey {
                host: "h".to_string(),
                port: 22,
            },
            "h",
            22,
        );
        assert!(matches!(unknown, SshError::UnknownHostKey { .. }));
    }

    #[test]
    fn generic_russh_error_is_never_the_bare_underlying_message() {
        let err = SshError::from(russh::Error::Disconnect);
        let msg = err.to_string();
        assert_ne!(msg, "Disconnected");
        assert!(msg.contains("retry"), "{msg}");
        assert!(msg.contains("(russh: Disconnected)"), "{msg}");
    }

    #[test]
    fn auth_failed_mentions_agent_and_identityfile() {
        let msg = SshError::AuthFailed {
            host: "web01".to_string(),
        }
        .to_string();
        assert!(msg.contains("ssh-agent"), "{msg}");
        assert!(msg.contains("IdentityFile"), "{msg}");
        assert!(msg.contains("ssh-add"), "{msg}");
    }
}
