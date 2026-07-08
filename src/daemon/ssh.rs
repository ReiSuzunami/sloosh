//! SSH connection establishment via `russh`, `~/.ssh/config` subset parsing
//! (`Host`, `HostName`, `Port`, `User`, `IdentityFile`, `ProxyJump`), and
//! `known_hosts` handling (DESIGN.md §2, §3).
//!
//! Trust posture for this milestone: **no vault, no lease enforcement**.
//! Any local caller that can reach the daemon's Unix socket (same-user,
//! mode 0600 — see `transport::unix`) can open SSH sessions to any host
//! reachable from `~/.ssh/config`. DESIGN.md §4's lease/vault layer lands in
//! milestone 3 and will gate this; until then the socket's own permissions
//! are the only access control (see the note in `daemon/mod.rs`).

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use russh::Pty;
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKey};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Everything that can go wrong establishing an SSH connection. Variants
/// carry self-teaching messages (DESIGN.md §7): the human reading a CLI
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
        "host key for {host}:{port} is not in ~/.ssh/known_hosts, so sloosh refuses to trust it. \
         Run `ssh {host}` by hand once, accept and record its fingerprint, then retry."
    )]
    UnknownHostKey { host: String, port: u16 },

    #[error(
        "REFUSING TO CONNECT: the host key presented by {host}:{port} does NOT match the one \
         recorded in ~/.ssh/known_hosts (line {line}). This usually means the host was reinstalled, \
         OR that you are the target of a man-in-the-middle attack. sloosh will not proceed \
         automatically — verify out of band and update known_hosts yourself if the change is expected."
    )]
    HostKeyMismatch {
        host: String,
        port: u16,
        line: usize,
    },

    #[error(
        "could not check the server's key against ~/.ssh/known_hosts — make sure the file \
         exists and is readable, then retry. (keys: {0})"
    )]
    KnownHosts(#[from] russh::keys::Error),

    #[error(
        "identity file {path} is passphrase-protected; sloosh never prompts for key passphrases. \
         Add it to ssh-agent first (`ssh-add {path}`) and sloosh will pick it up automatically."
    )]
    EncryptedIdentity { path: PathBuf },

    #[error(
        "no working authentication method for {host} (tried ssh-agent identities and unencrypted \
         IdentityFile keys from ~/.ssh/config; password auth via the vault lands in milestone 3). \
         Load a key into ssh-agent with `ssh-add`, or add an `IdentityFile` entry to ~/.ssh/config."
    )]
    AuthFailed { host: String },

    #[error(
        "ProxyJump chains (more than one hop) are not yet supported; sloosh only supports a single \
         jump host. Simplify the `ProxyJump` entry for this host to one hop."
    )]
    ProxyJumpChainUnsupported,

    /// Catch-all for `russh` protocol errors on an already-established
    /// connection (channel opens, PTY/shell requests, writes). Never let
    /// this be the bare underlying message (DESIGN.md §7): say what it
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

/// One `Host` block from `~/.ssh/config`, holding only the directives
/// DESIGN.md §2 promises to understand.
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
}

/// A parsed `~/.ssh/config` subset: an ordered list of `Host` blocks. Order
/// matters — like real `ssh_config`, the *first* matching block's value for
/// a given directive wins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshConfig {
    blocks: Vec<HostBlock>,
}

/// Resolved connection parameters for a host alias, after merging any
/// matching `~/.ssh/config` blocks over the built-in defaults (DESIGN.md
/// §2: "a host not in config is treated as a literal hostname, default user
/// = local user, port 22").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostConfig {
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<PathBuf>,
    pub proxy_jump: Option<String>,
}

/// Warn once per unknown directive name for the lifetime of the process
/// (DESIGN.md §2: "未知指令警告而非静默忽略" — warn, don't silently drop, but
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
             IdentityFile/ProxyJump — ignoring this line rather than guessing what it means"
        );
    }
}

impl SshConfig {
    /// Parse the subset of `~/.ssh/config` directives DESIGN.md §2 promises.
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

    /// Resolve `alias` against this config, falling back to the DESIGN.md
    /// §2 defaults (literal hostname, local user, port 22) for anything no
    /// matching block sets.
    pub fn resolve(&self, alias: &str) -> HostConfig {
        let mut cfg = HostConfig {
            alias: alias.to_string(),
            hostname: alias.to_string(),
            port: 22,
            user: current_user(),
            identity_files: Vec::new(),
            proxy_jump: None,
        };
        let mut hostname_set = false;
        let mut port_set = false;
        let mut user_set = false;
        let mut proxy_jump_set = false;

        for block in &self.blocks {
            if !host_patterns_match(&block.patterns, alias) {
                continue;
            }
            if !hostname_set && let Some(h) = &block.hostname {
                cfg.hostname = h.clone();
                hostname_set = true;
            }
            if !port_set && let Some(p) = block.port {
                cfg.port = p;
                port_set = true;
            }
            if !user_set && let Some(u) = &block.user {
                cfg.user = u.clone();
                user_set = true;
            }
            if !proxy_jump_set && let Some(pj) = &block.proxy_jump {
                cfg.proxy_jump = Some(pj.clone());
                proxy_jump_set = true;
            }
            // IdentityFile is cumulative across matching blocks, like real ssh_config.
            cfg.identity_files
                .extend(block.identity_files.iter().cloned());
        }
        cfg
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

/// Resolve the local user for the "no config entry" default (DESIGN.md §2).
fn current_user() -> String {
    if let Ok(u) = std::env::var("USER")
        && !u.is_empty()
    {
        return u;
    }
    if let Ok(u) = std::env::var("LOGNAME")
        && !u.is_empty()
    {
        return u;
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
    /// Kept alive only to hold the `ProxyJump` hop's connection open for as
    /// long as `handle`'s tunneled channel needs it; never read directly.
    _jump: Option<Box<russh::client::Handle<Handler>>>,
}

/// `russh::client::Handler` doing strict host-key verification against
/// `~/.ssh/known_hosts` (DESIGN.md §2 "known_hosts hash 条目支持"). No other
/// callback is overridden — defaults are fine for a plain interactive shell
/// client.
pub struct Handler {
    host: String,
    port: u16,
}

impl russh::client::Handler for Handler {
    type Error = SshError;

    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool, SshError> {
        match russh::keys::check_known_hosts(&self.host, self.port, server_public_key) {
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
}

/// Connect to `alias`, resolving it through `~/.ssh/config`, handling a
/// single `ProxyJump` hop if configured, verifying the host key, and
/// authenticating via ssh-agent then unencrypted `IdentityFile` keys
/// (DESIGN.md §2, §3).
pub async fn connect(alias: &str) -> Result<Connection, SshError> {
    let config = SshConfig::load_default();
    let host_cfg = config.resolve(alias);
    connect_resolved(&config, host_cfg).await
}

async fn connect_resolved(
    config: &SshConfig,
    host_cfg: HostConfig,
) -> Result<Connection, SshError> {
    if let Some(jump_spec) = host_cfg.proxy_jump.clone() {
        return connect_via_proxy_jump(config, &jump_spec, host_cfg).await;
    }

    let tcp = open_tcp(&host_cfg.hostname, host_cfg.port).await?;
    let handle = connect_over_stream(tcp, &host_cfg).await?;
    Ok(Connection {
        handle,
        resolved: host_cfg,
        _jump: None,
    })
}

async fn connect_via_proxy_jump(
    config: &SshConfig,
    jump_spec: &str,
    target_cfg: HostConfig,
) -> Result<Connection, SshError> {
    if jump_spec.contains(',') {
        return Err(SshError::ProxyJumpChainUnsupported);
    }
    let mut jump_cfg = config.resolve(parse_proxy_jump_alias(jump_spec));
    apply_proxy_jump_overrides(jump_spec, &mut jump_cfg);
    if jump_cfg.proxy_jump.is_some() {
        // A jump host that itself needs a jump host would be a two-hop
        // chain; refuse rather than silently doing the wrong thing.
        return Err(SshError::ProxyJumpChainUnsupported);
    }

    let jump_tcp = open_tcp(&jump_cfg.hostname, jump_cfg.port).await?;
    let jump_handle = connect_over_stream(jump_tcp, &jump_cfg).await?;

    let channel = jump_handle
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
    let handle = connect_over_stream(stream, &target_cfg).await?;

    Ok(Connection {
        handle,
        resolved: target_cfg,
        _jump: Some(Box::new(jump_handle)),
    })
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
    if let Some((_, port_str)) = host_part.split_once(':')
        && let Ok(port) = port_str.parse::<u16>()
    {
        cfg.port = port;
    }
}

/// Resolve `host` and open a TCP connection, trying every resolved address
/// (v4 and v6) like real `ssh` does. Failures are classified so the
/// agent-facing message says what actually went wrong: DNS vs refused vs
/// timeout vs anything else (DESIGN.md §7 — errors are teaching material).
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
) -> Result<russh::client::Handle<Handler>, SshError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = Arc::new(russh::client::Config::default());
    let handler = Handler {
        host: host_cfg.hostname.clone(),
        port: host_cfg.port,
    };
    let mut handle = russh::client::connect_stream(config, stream, handler)
        .await
        .map_err(|e| add_handshake_context(e, &host_cfg.hostname, host_cfg.port))?;
    authenticate(&mut handle, host_cfg).await?;
    Ok(handle)
}

/// Auth order (DESIGN.md §2, §3): ssh-agent identities first, then
/// unencrypted `IdentityFile` keys. Password auth is deliberately **not**
/// implemented here — see the seam below — it needs the vault (milestone 3)
/// to source a credential without the plaintext ever touching the CLI or
/// the agent's context.
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

    // ---- M3 seam -----------------------------------------------------
    // Password auth belongs here: fetch a credential for `host_cfg.alias`
    // out of the unlocked vault (never from a CLI argument — DESIGN.md §4)
    // and call `handle.authenticate_password(&host_cfg.user, password)`,
    // zeroizing the password immediately after. Not implemented in
    // milestone 2: there is no vault yet.
    // --------------------------------------------------------------------

    if let Some(path) = encrypted_identities.into_iter().next() {
        return Err(SshError::EncryptedIdentity { path });
    }
    Err(SshError::AuthFailed {
        host: host_cfg.alias.clone(),
    })
}

/// Try every identity ssh-agent offers. Returns `Ok(true)` on success,
/// `Ok(false)` if the agent is unreachable/empty or rejected everything
/// (not a hard error — DESIGN.md §2 says agent auth is tried first, not
/// that it's required), and `Err` only for a genuine signing failure that
/// should stop the auth attempt.
async fn try_agent_auth(
    handle: &mut russh::client::Handle<Handler>,
    host_cfg: &HostConfig,
    hash_alg: Option<HashAlg>,
) -> Result<bool, SshError> {
    let Ok(mut agent) = russh::keys::agent::client::AgentClient::connect_env().await else {
        return Ok(false);
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

/// Terminal modes requested for every session PTY: echo off (DESIGN.md §3
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
    fn proxy_jump_chain_is_rejected() {
        let contents = "Host inner\n    ProxyJump hop1,hop2\n";
        let cfg = SshConfig::parse(contents);
        let resolved = cfg.resolve("inner");
        assert_eq!(resolved.proxy_jump.as_deref(), Some("hop1,hop2"));
        // The actual rejection happens in connect_via_proxy_jump, which
        // needs a live connection to exercise end-to-end (see the
        // SLOOSH_TEST_SSH_HOST-gated integration test).
    }

    #[test]
    fn parse_proxy_jump_alias_strips_user_and_port() {
        assert_eq!(parse_proxy_jump_alias("bastion"), "bastion");
        assert_eq!(parse_proxy_jump_alias("user@bastion"), "bastion");
        assert_eq!(parse_proxy_jump_alias("user@bastion:2200"), "bastion");
    }

    // -- error Display formatting: every agent-facing message must say what
    //    failed AND what to do next, with the raw error only as detail
    //    (DESIGN.md §7). -----------------------------------------------------

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
