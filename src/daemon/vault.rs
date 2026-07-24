//! Encrypted credential vault at `~/.sloosh/vault` (docs/internals/architecture.md).
//!
//! On-disk format is a small versioned JSON envelope:
//!
//! ```json
//! {
//!   "version": 2,
//!   "kdf": { "m_cost": 65536, "t_cost": 3, "p_cost": 4, "salt": "<hex>" },
//!   "nonce": "<hex>",
//!   "ciphertext": "<hex>"
//! }
//! ```
//!
//! The plaintext sealed inside `ciphertext` is a [`VaultData`]: a map from
//! alias to [`HostEntry`]. The master password is run through Argon2id
//! (parameters recorded alongside the ciphertext, so changing the defaults
//! in a later build doesn't break old vaults) to derive a 32-byte key, which
//! is used directly as a ChaCha20-Poly1305 key. There is no separate
//! password verifier: successful AEAD decryption *is* the password check,
//! and a fresh random nonce is written on every save.
//!
//! Secrets never appear in logs, error messages, or `Debug` output — see the
//! manual `Debug` impls below. Master password buffers, derived keys, and
//! decrypted plaintext are zeroized wherever feasible.
//!
//! This module also owns the in-memory "unlocked vault" cache: while at
//! least one lease is active (see `daemon/lease.rs`), the derived key (and
//! decrypted entries) are kept around so authenticated SSH connections can
//! be established without re-prompting for the master password on every
//! call. The cache is cleared the moment the last lease expires
//! (`clear_cache`, called from `daemon/lease.rs`).

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;
use zeroize::{Zeroize, Zeroizing};

use crate::proto::{HostAuthKind, HostRoute};
use crate::transport::unix::{ensure_private_dir, sloosh_home};

/// Argon2id memory cost in KiB (64 MiB). docs/internals/architecture.md asks for "m=64MiB
/// t=3 p=4" as a reasonable starting point for a locally-run daemon.
const KDF_M_COST: u32 = 64 * 1024;
const KDF_T_COST: u32 = 3;
const KDF_P_COST: u32 = 4;
const KDF_OUTPUT_LEN: usize = 32;
const SALT_LEN: usize = 16;
const MAX_HOST_ALIAS_BYTES: usize = 255;
const MAX_HOSTNAME_BYTES: usize = 255;
const MAX_HOST_USER_BYTES: usize = 255;
const MAX_JUMP_BYTES: usize = 1024;
const MAX_MANAGED_ROUTE_HOPS: usize = 8;

const VAULT_VERSION: u32 = 2;
const LEGACY_VAULT_VERSION: u32 = 1;

/// Standard vault location: `~/.sloosh/vault`.
pub fn vault_path() -> PathBuf {
    sloosh_home().join("vault")
}

// ---------------------------------------------------------------------
// Hex helpers (hand-rolled rather than pulling in a crate for 8 bytes of
// encoding logic).
// ---------------------------------------------------------------------

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, VaultError> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(VaultError::TamperedOrCorrupt);
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = nibble(chunk[0]).ok_or(VaultError::TamperedOrCorrupt)?;
        let lo = nibble(chunk[1]).ok_or(VaultError::TamperedOrCorrupt)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// On-disk envelope
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KdfParamsFile {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    /// Hex-encoded random salt, fresh on every save (we always re-encrypt
    /// the whole vault, so there's no reason to keep an old salt around).
    salt: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    kdf: KdfParamsFile,
    /// Hex-encoded 12-byte ChaCha20-Poly1305 nonce, fresh on every write.
    nonce: String,
    /// Hex-encoded ciphertext (includes the Poly1305 tag).
    ciphertext: String,
}

// ---------------------------------------------------------------------
// Plaintext contents
// ---------------------------------------------------------------------

/// Decrypted vault contents: alias -> host credential entry.
///
/// Deliberately has no `#[derive(Debug)]` — see the manual impl below,
/// which redacts everything so a stray `{:?}` in a log line can never leak
/// a password.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct VaultData {
    #[serde(default)]
    pub hosts: HashMap<String, HostEntry>,
}

impl fmt::Debug for VaultData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultData")
            .field("hosts", &format!("<{} entries redacted>", self.hosts.len()))
            .finish()
    }
}

impl Drop for VaultData {
    fn drop(&mut self) {
        for entry in self.hosts.values_mut() {
            entry.zeroize_secrets();
        }
    }
}

/// One vault entry: enough connection info to dial a host plus an auth
/// method. Vault version 2 adds explicit agent/key-file authentication and
/// typed routes; version 1 plaintext is accepted and migrated on next write.
#[derive(Clone, Serialize, Deserialize)]
pub struct HostEntry {
    pub hostname: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub user: Option<String>,
    pub auth: AuthMethod,
    /// `alias = "jump"` accepts version-1 plaintext. The custom decoder maps
    /// `null` to Direct and a legacy string to advanced ProxyJump semantics.
    #[serde(default, alias = "jump", deserialize_with = "deserialize_host_route")]
    pub route: HostRoute,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StoredRoute {
    Typed(HostRoute),
    Legacy(String),
}

fn deserialize_host_route<'de, D>(deserializer: D) -> Result<HostRoute, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Option::<StoredRoute>::deserialize(deserializer)? {
        None => HostRoute::Direct,
        Some(StoredRoute::Typed(route)) => route,
        Some(StoredRoute::Legacy(spec)) => HostRoute::ProxyJump { spec },
    })
}

/// Connection metadata safe to return to human management clients.
/// Authentication material is deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostMetadata {
    pub alias: String,
    pub hostname: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub auth: HostAuthKind,
    pub route: HostRoute,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostUpdate {
    pub alias: String,
    pub hostname: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub route: HostRoute,
}

impl HostEntry {
    fn zeroize_secrets(&mut self) {
        self.auth.zeroize_secrets();
    }
}

impl fmt::Debug for HostEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostEntry")
            .field("hostname", &self.hostname)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("auth", &self.auth)
            .field("route", &self.route)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthMethod {
    Password { password: String },
    Agent,
    KeyFile { path: String },
}

impl AuthMethod {
    pub fn kind(&self) -> HostAuthKind {
        match self {
            Self::Password { .. } => HostAuthKind::Password,
            Self::Agent => HostAuthKind::Agent,
            Self::KeyFile { .. } => HostAuthKind::KeyFile,
        }
    }
}

impl AuthMethod {
    fn zeroize_secrets(&mut self) {
        match self {
            AuthMethod::Password { password } => password.zeroize(),
            AuthMethod::Agent | AuthMethod::KeyFile { .. } => {}
        }
    }
}

impl fmt::Debug for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthMethod::Password { .. } => f
                .debug_struct("Password")
                .field("password", &"<redacted>")
                .finish(),
            AuthMethod::Agent => f.write_str("Agent"),
            AuthMethod::KeyFile { path } => f.debug_struct("KeyFile").field("path", path).finish(),
        }
    }
}

// ---------------------------------------------------------------------
// Errors — self-teaching per docs/internals/architecture.md.
// ---------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error(
        "no vault at {path} yet — this is a brand-new sloosh install; a human needs to run \
         `sloosh vault init` (or `sloosh host add <alias> --hostname <host>`) in a real terminal \
         to create one and set a master password"
    )]
    NotFound { path: PathBuf },

    #[error(
        "vault file at {path} is not valid sloosh-vault JSON — it may be corrupted; restore \
         from backup or delete it and re-add your hosts with `sloosh host add` (cause: {source})"
    )]
    Corrupt {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error(
        "wrong master password (vault decryption failed) — try again; there is no recovery if \
         you've forgotten it, other than deleting ~/.sloosh/vault and re-adding your hosts"
    )]
    WrongPassword,

    #[error(
        "vault file is corrupt (bad hex encoding in one of its fields) — it has been damaged; \
         restore from backup or delete it and re-add your hosts"
    )]
    TamperedOrCorrupt,

    #[error(
        "the KDF parameters recorded in the vault file are invalid (cause: {0}) — the file is \
         likely corrupt"
    )]
    BadKdfParams(String),

    #[error("failed to read {path} (cause: {source})")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to write {path} (cause: {source})")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("no host entry named '{0}' in the vault — run `sloosh host add {0} --hostname <host>`")]
    NoSuchHost(String),

    #[error("'{0}' is already in the vault — use `sloosh host edit {0}` or remove it first")]
    HostExists(String),

    #[error("cannot remove '{alias}' because these managed routes depend on it: {dependents}")]
    HostInUse { alias: String, dependents: String },

    #[error("invalid host metadata: {0}")]
    InvalidHost(String),

    #[error(
        "vault format version {found} is newer than this Sloosh build supports (latest: {supported}); upgrade Sloosh before opening it"
    )]
    UnsupportedVersion { found: u32, supported: u32 },

    #[error("a vault already exists at {0}; this function is only for first-time creation")]
    AlreadyExists(PathBuf),
}

// ---------------------------------------------------------------------
// KDF + AEAD primitives
// ---------------------------------------------------------------------

fn derive_key(password: &[u8], kdf: &KdfParamsFile) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let salt = hex_decode(&kdf.salt)?;
    let params = Argon2Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(KDF_OUTPUT_LEN))
        .map_err(|e| VaultError::BadKdfParams(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KDF_OUTPUT_LEN]);
    argon2
        .hash_password_into(password, &salt, out.as_mut_slice())
        .map_err(|e| VaultError::BadKdfParams(e.to_string()))?;
    Ok(out)
}

fn encrypt_data(data: &VaultData, key: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12]), VaultError> {
    let plaintext =
        serde_json::to_vec(data).expect("VaultData always serializes: no non-finite floats etc.");
    let mut plaintext = Zeroizing::new(plaintext);

    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);

    let cipher_key = Key::from(*key);
    let cipher = ChaCha20Poly1305::new(&cipher_key);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .expect("ChaCha20-Poly1305 encryption of a bounded in-memory buffer cannot fail");
    plaintext.zeroize();
    Ok((ciphertext, nonce_bytes))
}

fn decrypt_data(
    ciphertext: &[u8],
    nonce_bytes: &[u8],
    key: &[u8; 32],
    path: &Path,
) -> Result<VaultData, VaultError> {
    let nonce_array: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| VaultError::TamperedOrCorrupt)?;
    let cipher_key = Key::from(*key);
    let cipher = ChaCha20Poly1305::new(&cipher_key);
    let nonce = Nonce::from(nonce_array);
    let mut plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| VaultError::WrongPassword)?;
    let result: Result<VaultData, _> = serde_json::from_slice(&plaintext);
    plaintext.zeroize();
    result.map_err(|source| VaultError::Corrupt {
        path: path.to_path_buf(),
        source,
    })
}

// ---------------------------------------------------------------------
// File I/O, parameterized over an explicit path so tests never touch the
// real `~/.sloosh/vault` (and don't need to race over process-wide env
// vars like `$HOME` to redirect it).
// ---------------------------------------------------------------------

fn read_vault_file(path: &Path) -> Result<VaultFile, VaultError> {
    let bytes = std::fs::read(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            VaultError::NotFound {
                path: path.to_path_buf(),
            }
        } else {
            VaultError::Read {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    serde_json::from_slice(&bytes).map_err(|source| VaultError::Corrupt {
        path: path.to_path_buf(),
        source,
    })
}

/// Process-wide writer lock for vault disk mutations. All production vault
/// writes are routed through the daemon, so serializing create/add/remove here
/// makes each read-modify-write transaction indivisible and prevents lost
/// updates between concurrent client connections.
fn vault_writer_guard() -> MutexGuard<'static, ()> {
    static WRITER: OnceLock<Mutex<()>> = OnceLock::new();
    WRITER
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Serializes each async read-modify-write through its cache refresh. The
/// disk writer lock alone is insufficient: without this outer lock, an older
/// writer can refresh the in-memory cache after a newer writer and make the
/// daemon temporarily forget the newer entry even though disk is correct.
fn vault_mutation_lock() -> &'static AsyncMutex<()> {
    static MUTATION: OnceLock<AsyncMutex<()>> = OnceLock::new();
    MUTATION.get_or_init(|| AsyncMutex::new(()))
}

fn write_vault_file_atomic(path: &Path, file: &VaultFile) -> Result<(), VaultError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        // Only harden sloosh's dedicated state directory. Explicit test paths
        // can live directly under /tmp; changing permissions there would be
        // unsafe. Validate ownership and reject symlinks before creating a
        // file containing secrets.
        if parent == sloosh_home() {
            ensure_private_dir(parent).map_err(|source| VaultError::Write {
                path: parent.to_path_buf(),
                source: io::Error::other(source),
            })?;
        } else {
            std::fs::create_dir_all(parent).map_err(|source| VaultError::Write {
                path: path.to_path_buf(),
                source,
            })?;
        }
    }
    let mut suffix = [0u8; 8];
    rand::rng().fill_bytes(&mut suffix);
    let tmp_path = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        hex_encode(&suffix)
    ));
    let json = serde_json::to_vec_pretty(file).expect("VaultFile always serializes");
    // Created 0600 *at open time* (not chmod'd afterwards), so there is no
    // window — however brief — in which another same-machine user could open
    // the temp file under a permissive default umask.
    let mut tmp = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|source| VaultError::Write {
            path: tmp_path.clone(),
            source,
        })?;
    let result = tmp
        .write_all(&json)
        .and_then(|()| tmp.sync_all())
        .map_err(|source| VaultError::Write {
            path: tmp_path.clone(),
            source,
        });
    drop(tmp);
    let result = result.and_then(|()| {
        std::fs::rename(&tmp_path, path).map_err(|source| VaultError::Write {
            path: path.to_path_buf(),
            source,
        })
    });
    let result = result.and_then(|()| {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| VaultError::Write {
                path: parent.to_path_buf(),
                source,
            })
    });
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

/// Encrypt `data` under `password` using fresh KDF params (new salt) and
/// write it to `path`, replacing anything already there.
fn save_new_at(path: &Path, data: &VaultData, password: &[u8]) -> Result<(), VaultError> {
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    let kdf = KdfParamsFile {
        m_cost: KDF_M_COST,
        t_cost: KDF_T_COST,
        p_cost: KDF_P_COST,
        salt: hex_encode(&salt),
    };
    let key = derive_key(password, &kdf)?;
    let (ciphertext, nonce) = encrypt_data(data, &key)?;
    let file = VaultFile {
        version: VAULT_VERSION,
        kdf,
        nonce: hex_encode(&nonce),
        ciphertext: hex_encode(&ciphertext),
    };
    write_vault_file_atomic(path, &file)
}

/// Open the vault at `path` with `password`, verifying the password by
/// virtue of successful AEAD decryption (there is no separate verifier).
fn unlock_material_at(
    path: &Path,
    password: &[u8],
) -> Result<(VaultData, KdfParamsFile, Zeroizing<[u8; 32]>), VaultError> {
    let VaultFile {
        version,
        kdf,
        nonce,
        ciphertext,
    } = read_vault_file(path)?;
    if version != LEGACY_VAULT_VERSION && version != VAULT_VERSION {
        return Err(VaultError::UnsupportedVersion {
            found: version,
            supported: VAULT_VERSION,
        });
    }
    let key = derive_key(password, &kdf)?;
    let nonce = hex_decode(&nonce)?;
    let ciphertext = hex_decode(&ciphertext)?;
    let data = decrypt_data(&ciphertext, &nonce, &key, path)?;
    Ok((data, kdf, key))
}

fn unlock_at(path: &Path, password: &[u8]) -> Result<VaultData, VaultError> {
    unlock_material_at(path, password).map(|(data, _, _)| data)
}

fn create_at(path: &Path, data: &VaultData, password: &[u8]) -> Result<(), VaultError> {
    let _writer = vault_writer_guard();
    if path.exists() {
        return Err(VaultError::AlreadyExists(path.to_path_buf()));
    }
    save_new_at(path, data, password)
}

fn validate_host_field(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), VaultError> {
    if value.trim().is_empty() {
        return Err(VaultError::InvalidHost(format!("{field} cannot be empty")));
    }
    if value.len() > max_bytes {
        return Err(VaultError::InvalidHost(format!(
            "{field} exceeds the {max_bytes}-byte limit"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(VaultError::InvalidHost(format!(
            "{field} cannot contain control characters"
        )));
    }
    Ok(())
}

fn validate_host_update(metadata: &HostUpdate) -> Result<(), VaultError> {
    validate_host_field("alias", &metadata.alias, MAX_HOST_ALIAS_BYTES)?;
    validate_host_field("hostname", &metadata.hostname, MAX_HOSTNAME_BYTES)?;
    if metadata.port == Some(0) {
        return Err(VaultError::InvalidHost(
            "port must be between 1 and 65535".to_string(),
        ));
    }
    if let Some(user) = &metadata.user {
        validate_host_field("user", user, MAX_HOST_USER_BYTES)?;
    }
    match &metadata.route {
        HostRoute::Direct => {}
        HostRoute::ManagedHost { alias } => {
            validate_host_field("managed host alias", alias, MAX_HOST_ALIAS_BYTES)?;
            if alias == &metadata.alias {
                return Err(VaultError::InvalidHost(
                    "a host cannot route through itself".to_string(),
                ));
            }
        }
        HostRoute::ProxyJump { spec } => {
            validate_host_field("ProxyJump", spec, MAX_JUMP_BYTES)?;
        }
    }
    Ok(())
}

fn validate_auth(auth: &AuthMethod) -> Result<(), VaultError> {
    if let AuthMethod::KeyFile { path } = auth {
        validate_host_field("key file path", path, MAX_JUMP_BYTES)?;
    }
    Ok(())
}

fn validate_managed_route(
    data: &VaultData,
    owner: &str,
    route: &HostRoute,
) -> Result<(), VaultError> {
    if let HostRoute::ManagedHost { alias } = route {
        if !data.hosts.contains_key(alias) {
            return Err(VaultError::InvalidHost(format!(
                "managed route host '{alias}' does not exist; add that host profile first"
            )));
        }
        let mut seen = std::collections::HashSet::from([owner.to_string()]);
        let mut current = alias.as_str();
        for _ in 0..MAX_MANAGED_ROUTE_HOPS {
            if !seen.insert(current.to_string()) {
                return Err(VaultError::InvalidHost(format!(
                    "managed route creates a cycle through '{current}'"
                )));
            }
            let Some(entry) = data.hosts.get(current) else {
                return Ok(());
            };
            match &entry.route {
                HostRoute::ManagedHost { alias } => current = alias,
                HostRoute::Direct | HostRoute::ProxyJump { .. } => return Ok(()),
            }
        }
        return Err(VaultError::InvalidHost(format!(
            "managed route exceeds the {MAX_MANAGED_ROUTE_HOPS}-hop limit"
        )));
    }
    Ok(())
}

async fn add_entry_at(
    path: &Path,
    alias: &str,
    entry: HostEntry,
    password: &[u8],
    replace: bool,
) -> Result<(), VaultError> {
    validate_host_update(&HostUpdate {
        alias: alias.to_string(),
        hostname: entry.hostname.clone(),
        port: entry.port,
        user: entry.user.clone(),
        route: entry.route.clone(),
    })?;
    validate_auth(&entry.auth)?;
    let _mutation = vault_mutation_lock().lock().await;
    let data = {
        let _writer = vault_writer_guard();
        let mut data = if path.exists() {
            unlock_at(path, password)?
        } else {
            VaultData::default()
        };
        if !replace && data.hosts.contains_key(alias) {
            return Err(VaultError::HostExists(alias.to_string()));
        }
        validate_managed_route(&data, alias, &entry.route)?;
        data.hosts.insert(alias.to_string(), entry);
        save_new_at(path, &data, password)?;
        data
    };
    refresh_cache_if_present(path, &data, password).await;
    Ok(())
}

async fn rm_entry_at(path: &Path, alias: &str, password: &[u8]) -> Result<(), VaultError> {
    let _mutation = vault_mutation_lock().lock().await;
    let data = {
        let _writer = vault_writer_guard();
        let mut data = unlock_at(path, password)?;
        let mut dependents = data
            .hosts
            .iter()
            .filter_map(|(dependent, entry)| match &entry.route {
                HostRoute::ManagedHost { alias: route_alias } if route_alias == alias => {
                    Some(dependent.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        dependents.sort_unstable();
        if !dependents.is_empty() {
            return Err(VaultError::HostInUse {
                alias: alias.to_string(),
                dependents: dependents.join(", "),
            });
        }
        if data.hosts.remove(alias).is_none() {
            return Err(VaultError::NoSuchHost(alias.to_string()));
        }
        save_new_at(path, &data, password)?;
        data
    };
    refresh_cache_if_present(path, &data, password).await;
    Ok(())
}

fn list_entries_at(path: &Path, password: &[u8]) -> Result<Vec<HostMetadata>, VaultError> {
    let _writer = vault_writer_guard();
    let data = unlock_at(path, password)?;
    let mut hosts = data
        .hosts
        .iter()
        .map(|(alias, entry)| HostMetadata {
            alias: alias.clone(),
            hostname: entry.hostname.clone(),
            port: entry.port,
            user: entry.user.clone(),
            auth: entry.auth.kind(),
            route: entry.route.clone(),
        })
        .collect::<Vec<_>>();
    hosts.sort_unstable_by(|left, right| left.alias.cmp(&right.alias));
    Ok(hosts)
}

async fn update_entry_at(
    path: &Path,
    metadata: HostUpdate,
    new_auth: Option<AuthMethod>,
    password: &[u8],
) -> Result<(), VaultError> {
    validate_host_update(&metadata)?;
    if let Some(auth) = &new_auth {
        validate_auth(auth)?;
    }
    let _mutation = vault_mutation_lock().lock().await;
    let data = {
        let _writer = vault_writer_guard();
        let mut data = unlock_at(path, password)?;
        let HostUpdate {
            alias,
            hostname,
            port,
            user,
            route,
        } = metadata;
        validate_managed_route(&data, &alias, &route)?;
        let entry = data
            .hosts
            .get_mut(&alias)
            .ok_or_else(|| VaultError::NoSuchHost(alias.clone()))?;
        entry.hostname = hostname;
        entry.port = port;
        entry.user = user;
        entry.route = route;
        if let Some(new_auth) = new_auth {
            entry.auth.zeroize_secrets();
            entry.auth = new_auth;
        }
        save_new_at(path, &data, password)?;
        data
    };
    refresh_cache_if_present(path, &data, password).await;
    Ok(())
}

// ---------------------------------------------------------------------
// Public API — thin wrappers over the `_at` functions above, bound to the
// real `~/.sloosh/vault` path.
// ---------------------------------------------------------------------

/// True if a vault file exists on disk yet.
pub fn exists() -> bool {
    vault_path().exists()
}

/// Create a brand-new vault, seeded with `data` (often empty, or with the
/// first host being added), protected by `password`. Fails if a vault
/// already exists — callers should check `exists()` first and route to
/// `add_entry` instead.
pub fn create(data: &VaultData, password: &[u8]) -> Result<(), VaultError> {
    create_at(&vault_path(), data, password)
}

/// Decrypt the vault from disk with `password`. Does not touch the
/// in-memory cache; use `unlock_for_lease` for that.
pub fn unlock(password: &[u8]) -> Result<VaultData, VaultError> {
    unlock_at(&vault_path(), password)
}

/// Add (or replace, if `replace` is true) a host entry, re-encrypting and
/// saving the whole vault. Creates the vault if it doesn't exist yet.
/// Always operates against a fresh disk-based unlock rather than mutating
/// any in-memory cache directly; if a cache entry already exists it is
/// best-effort refreshed in place afterwards, but this function never
/// creates a cache entry that wasn't already there (the cache's lifetime is
/// owned by `daemon/lease.rs`, tied to active lease count).
pub async fn add_entry(
    alias: &str,
    entry: HostEntry,
    password: &[u8],
    replace: bool,
) -> Result<(), VaultError> {
    add_entry_at(&vault_path(), alias, entry, password, replace).await
}

/// Remove a host entry, re-encrypting and saving the whole vault.
pub async fn rm_entry(alias: &str, password: &[u8]) -> Result<(), VaultError> {
    rm_entry_at(&vault_path(), alias, password).await
}

/// Return sorted, non-secret host metadata after verifying the Master Password.
pub fn list_entries(password: &[u8]) -> Result<Vec<HostMetadata>, VaultError> {
    list_entries_at(&vault_path(), password)
}

/// Update an existing host atomically, preserving its SSH password unless a
/// replacement is supplied.
pub async fn update_entry(
    metadata: HostUpdate,
    new_auth: Option<AuthMethod>,
    password: &[u8],
) -> Result<(), VaultError> {
    update_entry_at(&vault_path(), metadata, new_auth, password).await
}

// ---------------------------------------------------------------------
// In-memory cache: the derived key + decrypted entries are kept around
// only while at least one lease is active (docs/internals/architecture.md). `daemon/lease.rs`
// is responsible for calling `clear_cache()` when the last lease expires.
// ---------------------------------------------------------------------

struct UnlockedVault {
    data: VaultData,
    kdf: KdfParamsFile,
    key: Zeroizing<[u8; 32]>,
}

fn cache() -> &'static AsyncMutex<Option<UnlockedVault>> {
    static CACHE: std::sync::OnceLock<AsyncMutex<Option<UnlockedVault>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| AsyncMutex::new(None))
}

/// Unlock the vault (verifying `password`) and populate the cache, for use
/// by `approve` when activating a new lease.
pub async fn unlock_for_lease(password: &[u8]) -> Result<(), VaultError> {
    unlock_for_lease_at(&vault_path(), password).await
}

async fn unlock_for_lease_at(path: &Path, password: &[u8]) -> Result<(), VaultError> {
    let _mutation = vault_mutation_lock().lock().await;
    let (data, kdf, key) = unlock_material_at(path, password)?;
    let mut guard = cache().lock().await;
    *guard = Some(UnlockedVault { data, kdf, key });
    Ok(())
}

/// Clear the cached key/data. Called by `daemon/lease.rs` once the last
/// active lease expires or is otherwise dropped. `VaultData` and the key
/// both zeroize themselves on drop.
pub async fn clear_cache() {
    let mut guard = cache().lock().await;
    *guard = None;
}

/// Whether the vault is currently cached in memory (i.e. at least one
/// lease is believed to be active).
pub async fn is_cached() -> bool {
    cache().lock().await.is_some()
}

/// Look up a host entry from the cache. Returns `None` if the vault isn't
/// currently unlocked, or if there's no entry for `alias` — both cases mean
/// "fall back to `~/.ssh/config` for this host" to the caller.
pub async fn get_entry(alias: &str) -> Option<HostEntry> {
    let guard = cache().lock().await;
    guard.as_ref()?.data.hosts.get(alias).cloned()
}

/// Whether the vault (cache) currently has an entry for `alias`.
pub async fn has_entry(alias: &str) -> bool {
    let guard = cache().lock().await;
    guard
        .as_ref()
        .is_some_and(|v| v.data.hosts.contains_key(alias))
}

/// Re-verify `password` against a cache entry that already exists, without
/// touching disk. Used as a cheap extra gate before a slow disk-based
/// operation when we already know a cache is populated. Deliberately not a
/// constant-time comparison: this daemon only ever talks to same-user local
/// callers over a 0600 socket, so a timing side-channel on an in-process
/// memory compare isn't in the threat model docs/internals/architecture.md is written
/// against (a remote attacker can't reach this code path at all).
pub async fn verify_password(password: &[u8]) -> Result<bool, VaultError> {
    let guard = cache().lock().await;
    let Some(cached) = guard.as_ref() else {
        return Ok(false);
    };
    let key = derive_key(password, &cached.kdf)?;
    Ok(key.as_slice() == cached.key.as_slice())
}

async fn refresh_cache_if_present(path: &Path, data: &VaultData, password: &[u8]) {
    let mut guard = cache().lock().await;
    if guard.is_some() {
        // Best effort: if this fails (e.g. we lost a race with a concurrent
        // password change) just drop the stale cache entirely rather than
        // leave something inconsistent cached; the next `approve` will
        // re-populate it correctly.
        match read_vault_file(path).and_then(|f| derive_key(password, &f.kdf).map(|k| (f, k))) {
            Ok((file, key)) => {
                *guard = Some(UnlockedVault {
                    data: data.clone(),
                    kdf: file.kdf,
                    key,
                });
            }
            Err(_) => {
                *guard = None;
            }
        }
    }
}

/// Serializes tests that read/write the process-global vault cache
/// (`cache()`) above. Shared between this module's own cache test and
/// `daemon::lease::tests`, which also drives the cache indirectly via
/// `approve_lease`/`is_cached`/`clear_cache` — without a shared lock, two
/// independent test threads race on the *contents* of the same global
/// (not just its locking), which is exactly what made
/// `cache_lifecycle_and_password_reverification` flaky under `cargo test`'s
/// default parallelism.
#[cfg(test)]
pub(crate) fn cache_test_lock() -> &'static AsyncMutex<()> {
    static LOCK: std::sync::OnceLock<AsyncMutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_vault_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sloosh-vault-test-{tag}-{}-{}.vault",
            std::process::id(),
            tag.len()
        ))
    }

    fn sample_entry() -> HostEntry {
        HostEntry {
            hostname: "example.com".to_string(),
            port: Some(22),
            user: Some("alice".to_string()),
            auth: AuthMethod::Password {
                password: "hunter2".to_string(),
            },
            route: HostRoute::Direct,
        }
    }

    #[test]
    fn host_entry_without_jump_field_still_deserializes() {
        // Simulates a version-1 vault entry before typed routes existed.
        let json = r#"{
            "hostname": "example.com",
            "port": 22,
            "user": "alice",
            "auth": { "type": "password", "password": "hunter2" }
        }"#;
        let entry: HostEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.hostname, "example.com");
        assert_eq!(entry.route, HostRoute::Direct);
    }

    #[test]
    fn version_one_jump_string_migrates_to_proxy_jump_route() {
        let json = r#"{
            "hostname": "example.com",
            "auth": { "type": "agent" },
            "jump": "bastion,edge"
        }"#;
        let entry: HostEntry = serde_json::from_str(json).unwrap();
        assert_eq!(
            entry.route,
            HostRoute::ProxyJump {
                spec: "bastion,edge".to_string()
            }
        );
    }

    #[test]
    fn auth_debug_redacts_password_and_labels_non_secret_methods() {
        let password = format!(
            "{:?}",
            AuthMethod::Password {
                password: "never-print-me".to_string()
            }
        );
        assert!(!password.contains("never-print-me"));
        assert!(password.contains("redacted"));
        assert_eq!(format!("{:?}", AuthMethod::Agent), "Agent");
        assert!(
            format!(
                "{:?}",
                AuthMethod::KeyFile {
                    path: "~/.ssh/id_ed25519".to_string()
                }
            )
            .contains("id_ed25519")
        );
    }

    #[test]
    fn newer_vault_envelope_fails_with_upgrade_message() {
        let path = temp_vault_path("future-version");
        let _ = std::fs::remove_file(&path);
        create_at(&path, &VaultData::default(), b"pw").unwrap();
        let mut file = read_vault_file(&path).unwrap();
        file.version = VAULT_VERSION + 1;
        write_vault_file_atomic(&path, &file).unwrap();
        let error = unlock_at(&path, b"pw").unwrap_err();
        assert!(matches!(error, VaultError::UnsupportedVersion { .. }));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn version_one_envelope_is_rewritten_as_version_two_on_mutation() {
        let path = temp_vault_path("legacy-envelope");
        let _ = std::fs::remove_file(&path);
        create_at(&path, &VaultData::default(), b"pw").unwrap();
        let mut file = read_vault_file(&path).unwrap();
        file.version = LEGACY_VAULT_VERSION;
        write_vault_file_atomic(&path, &file).unwrap();

        add_entry_at(&path, "web", sample_entry(), b"pw", false)
            .await
            .unwrap();
        assert_eq!(read_vault_file(&path).unwrap().version, VAULT_VERSION);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn round_trip_create_unlock() {
        let path = temp_vault_path("roundtrip");
        let _ = std::fs::remove_file(&path);

        let mut data = VaultData::default();
        data.hosts.insert("web".to_string(), sample_entry());

        create_at(&path, &data, b"correct horse battery staple").unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        let decrypted = unlock_at(&path, b"correct horse battery staple").unwrap();
        assert_eq!(decrypted.hosts.len(), 1);
        let entry = &decrypted.hosts["web"];
        assert_eq!(entry.hostname, "example.com");
        match &entry.auth {
            AuthMethod::Password { password } => assert_eq!(password, "hunter2"),
            AuthMethod::Agent | AuthMethod::KeyFile { .. } => panic!("wrong auth method"),
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wrong_password_fails() {
        let path = temp_vault_path("wrongpw");
        let _ = std::fs::remove_file(&path);

        let data = VaultData::default();
        create_at(&path, &data, b"correct password").unwrap();

        let err = unlock_at(&path, b"incorrect password").unwrap_err();
        assert!(matches!(err, VaultError::WrongPassword));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let path = temp_vault_path("tamper");
        let _ = std::fs::remove_file(&path);

        let data = VaultData::default();
        create_at(&path, &data, b"pw").unwrap();

        let mut file: VaultFile = {
            let bytes = std::fs::read(&path).unwrap();
            serde_json::from_slice(&bytes).unwrap()
        };
        // Flip a hex character in the ciphertext to corrupt the AEAD tag.
        let mut chars: Vec<char> = file.ciphertext.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        file.ciphertext = chars.into_iter().collect();
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        let err = unlock_at(&path, b"pw").unwrap_err();
        // AEAD decrypt failure is indistinguishable from wrong password by
        // design (that's the point of an AEAD tag), so this surfaces as
        // WrongPassword; the property under test is that it does NOT
        // decrypt to garbage silently.
        assert!(matches!(err, VaultError::WrongPassword));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn kdf_params_recorded_in_file_are_honored_on_read() {
        let path = temp_vault_path("kdfparams");
        let _ = std::fs::remove_file(&path);

        let data = VaultData::default();
        create_at(&path, &data, b"pw").unwrap();

        // Rewrite the file with deliberately unusual (but valid) KDF params
        // and a freshly-derived key/ciphertext under those params. If
        // `unlock_at` ignored the file's recorded params in favor of the
        // module's current constants, this would fail to decrypt even with
        // the right password.
        let unusual = KdfParamsFile {
            m_cost: KdfParamsFile::MIN_M_COST_FOR_TEST,
            t_cost: 1,
            p_cost: 1,
            salt: hex_encode(b"0123456789abcdef"),
        };
        let key = derive_key(b"pw", &unusual).unwrap();
        let (ciphertext, nonce) = encrypt_data(&data, &key).unwrap();
        let file = VaultFile {
            version: VAULT_VERSION,
            kdf: unusual,
            nonce: hex_encode(&nonce),
            ciphertext: hex_encode(&ciphertext),
        };
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        let decrypted = unlock_at(&path, b"pw").unwrap();
        assert_eq!(decrypted.hosts.len(), 0);

        let _ = std::fs::remove_file(&path);
    }

    impl KdfParamsFile {
        const MIN_M_COST_FOR_TEST: u32 = 8 * 8; // Params::MIN_M_COST is 8*p_cost
    }

    #[tokio::test]
    async fn add_and_remove_entry_round_trip() {
        let _cache_guard = cache_test_lock().lock().await;
        clear_cache().await;
        let path = temp_vault_path("addrm");
        let _ = std::fs::remove_file(&path);

        add_entry_at(&path, "web", sample_entry(), b"pw", false)
            .await
            .unwrap();
        let data = unlock_at(&path, b"pw").unwrap();
        assert!(data.hosts.contains_key("web"));

        // Duplicate add without replace should fail.
        let err = add_entry_at(&path, "web", sample_entry(), b"pw", false)
            .await
            .unwrap_err();
        assert!(matches!(err, VaultError::HostExists(_)));

        rm_entry_at(&path, "web", b"pw").await.unwrap();
        let data = unlock_at(&path, b"pw").unwrap();
        assert!(!data.hosts.contains_key("web"));

        let err = rm_entry_at(&path, "web", b"pw").await.unwrap_err();
        assert!(matches!(err, VaultError::NoSuchHost(_)));

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn list_update_refreshes_cache_and_rotates_password() {
        let _cache_guard = cache_test_lock().lock().await;
        clear_cache().await;
        let path = temp_vault_path("list-update");
        let _ = std::fs::remove_file(&path);

        let mut data = VaultData::default();
        data.hosts.insert("web".to_string(), sample_entry());
        let mut bastion = sample_entry();
        bastion.hostname = "bastion.example.com".to_string();
        data.hosts.insert("bastion".to_string(), bastion);
        create_at(&path, &data, b"pw").unwrap();
        unlock_for_lease_at(&path, b"pw").await.unwrap();

        let hosts = list_entries_at(&path, b"pw").unwrap();
        assert_eq!(
            hosts
                .iter()
                .map(|host| host.alias.as_str())
                .collect::<Vec<_>>(),
            vec!["bastion", "web"]
        );

        update_entry_at(
            &path,
            HostUpdate {
                alias: "web".to_string(),
                hostname: "web.internal.example".to_string(),
                port: Some(2222),
                user: Some("deploy".to_string()),
                route: HostRoute::ManagedHost {
                    alias: "bastion".to_string(),
                },
            },
            None,
            b"pw",
        )
        .await
        .unwrap();

        let updated = unlock_at(&path, b"pw").unwrap();
        let entry = updated.hosts.get("web").unwrap();
        assert_eq!(entry.hostname, "web.internal.example");
        assert_eq!(entry.port, Some(2222));
        assert_eq!(entry.user.as_deref(), Some("deploy"));
        assert_eq!(
            entry.route,
            HostRoute::ManagedHost {
                alias: "bastion".to_string()
            }
        );
        let AuthMethod::Password { password } = &entry.auth else {
            panic!("password auth should be preserved");
        };
        assert_eq!(password, "hunter2");

        let cached = get_entry("web").await.unwrap();
        assert_eq!(cached.hostname, "web.internal.example");
        assert_eq!(
            cached.route,
            HostRoute::ManagedHost {
                alias: "bastion".to_string()
            }
        );

        let cycle = update_entry_at(
            &path,
            HostUpdate {
                alias: "bastion".to_string(),
                hostname: "bastion.example.com".to_string(),
                port: None,
                user: None,
                route: HostRoute::ManagedHost {
                    alias: "web".to_string(),
                },
            },
            None,
            b"pw",
        )
        .await
        .unwrap_err();
        assert!(matches!(cycle, VaultError::InvalidHost(message) if message.contains("cycle")));

        let error = rm_entry_at(&path, "bastion", b"pw").await.unwrap_err();
        assert!(matches!(error, VaultError::HostInUse { alias, .. } if alias == "bastion"));

        update_entry_at(
            &path,
            HostUpdate {
                alias: "web".to_string(),
                hostname: "web.internal.example".to_string(),
                port: Some(2222),
                user: Some("deploy".to_string()),
                route: HostRoute::ManagedHost {
                    alias: "bastion".to_string(),
                },
            },
            Some(AuthMethod::Password {
                password: "rotated-password".to_string(),
            }),
            b"pw",
        )
        .await
        .unwrap();
        let cached = get_entry("web").await.unwrap();
        let AuthMethod::Password { password } = &cached.auth else {
            panic!("password auth should be replaced");
        };
        assert_eq!(password, "rotated-password");

        let err = update_entry_at(
            &path,
            HostUpdate {
                alias: "missing".to_string(),
                hostname: "missing.example.com".to_string(),
                port: None,
                user: None,
                route: HostRoute::Direct,
            },
            None,
            b"pw",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VaultError::NoSuchHost(alias) if alias == "missing"));

        clear_cache().await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn host_mutations_reject_invalid_metadata_before_writing() {
        let _cache_guard = cache_test_lock().lock().await;
        clear_cache().await;
        let path = temp_vault_path("invalid-hosts");
        let _ = std::fs::remove_file(&path);

        let err = add_entry_at(&path, "", sample_entry(), b"pw", false)
            .await
            .unwrap_err();
        assert!(matches!(err, VaultError::InvalidHost(_)));
        assert!(!path.exists());

        let mut bad_port = sample_entry();
        bad_port.port = Some(0);
        let err = add_entry_at(&path, "web", bad_port, b"pw", false)
            .await
            .unwrap_err();
        assert!(matches!(err, VaultError::InvalidHost(_)));

        let err = add_entry_at(
            &path,
            "a".repeat(MAX_HOST_ALIAS_BYTES + 1).as_str(),
            sample_entry(),
            b"pw",
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VaultError::InvalidHost(_)));

        let err = update_entry_at(
            &path,
            HostUpdate {
                alias: "web".to_string(),
                hostname: "server.example.com".to_string(),
                port: None,
                user: Some("line\nbreak".to_string()),
                route: HostRoute::Direct,
            },
            None,
            b"pw",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VaultError::InvalidHost(_)));

        let err = update_entry_at(
            &path,
            HostUpdate {
                alias: "web".to_string(),
                hostname: "server.example.com".to_string(),
                port: None,
                user: None,
                route: HostRoute::ManagedHost {
                    alias: "web".to_string(),
                },
            },
            None,
            b"pw",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VaultError::InvalidHost(_)));
        assert!(!path.exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_adds_preserve_every_entry() {
        use std::sync::Arc;

        let _cache_guard = cache_test_lock().lock().await;
        clear_cache().await;
        const WRITERS: usize = 2;
        let path = temp_vault_path("concurrent-add");
        let _ = std::fs::remove_file(&path);
        create_at(&path, &VaultData::default(), b"pw").unwrap();
        let file = read_vault_file(&path).unwrap();
        let key = derive_key(b"pw", &file.kdf).unwrap();
        *cache().lock().await = Some(UnlockedVault {
            data: VaultData::default(),
            kdf: file.kdf,
            key,
        });

        let barrier = Arc::new(tokio::sync::Barrier::new(WRITERS));
        let mut tasks = Vec::with_capacity(WRITERS);
        for i in 0..WRITERS {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let alias = format!("host-{i}");
                let mut entry = sample_entry();
                entry.hostname = format!("host-{i}.example.com");
                add_entry_at(&path, &alias, entry, b"pw", false).await
            }));
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }

        let data = unlock_at(&path, b"pw").unwrap();
        assert_eq!(data.hosts.len(), WRITERS);
        for i in 0..WRITERS {
            assert!(data.hosts.contains_key(&format!("host-{i}")));
            assert!(
                get_entry(&format!("host-{i}")).await.is_some(),
                "cache must retain every serialized mutation"
            );
        }

        clear_cache().await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_unlock_and_remove_never_recaches_removed_entry() {
        use std::sync::Arc;

        let _cache_guard = cache_test_lock().lock().await;
        clear_cache().await;
        let path = temp_vault_path("concurrent-unlock-remove");
        let _ = std::fs::remove_file(&path);
        let mut data = VaultData::default();
        data.hosts.insert("web".to_string(), sample_entry());
        create_at(&path, &data, b"pw").unwrap();

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let unlock_path = path.clone();
        let unlock_barrier = Arc::clone(&barrier);
        let unlock = tokio::spawn(async move {
            unlock_barrier.wait().await;
            unlock_for_lease_at(&unlock_path, b"pw").await
        });
        let remove_path = path.clone();
        let remove_barrier = Arc::clone(&barrier);
        let remove = tokio::spawn(async move {
            remove_barrier.wait().await;
            rm_entry_at(&remove_path, "web", b"pw").await
        });

        unlock.await.unwrap().unwrap();
        remove.await.unwrap().unwrap();
        assert!(get_entry("web").await.is_none());
        assert!(!unlock_at(&path, b"pw").unwrap().hosts.contains_key("web"));

        clear_cache().await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn cache_lifecycle_and_password_reverification() {
        let _guard = cache_test_lock().lock().await;
        let path = temp_vault_path("cache");
        let _ = std::fs::remove_file(&path);
        let data = VaultData::default();
        create_at(&path, &data, b"pw").unwrap();

        assert!(!is_cached().await);
        assert!(!verify_password(b"pw").await.unwrap());

        // Simulate unlock_for_lease against this temp path directly (the
        // public wrapper is bound to the real vault_path(), so exercise the
        // same logic inline here).
        {
            let file = read_vault_file(&path).unwrap();
            let key = derive_key(b"pw", &file.kdf).unwrap();
            let mut guard = cache().lock().await;
            *guard = Some(UnlockedVault {
                data: unlock_at(&path, b"pw").unwrap(),
                kdf: file.kdf,
                key,
            });
        }

        assert!(is_cached().await);
        assert!(verify_password(b"pw").await.unwrap());
        assert!(!verify_password(b"wrong").await.unwrap());

        clear_cache().await;
        assert!(!is_cached().await);

        let _ = std::fs::remove_file(&path);
    }
}
