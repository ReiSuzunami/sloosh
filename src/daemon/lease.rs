//! Authorization leases: process-ancestry anchoring, pending-request /
//! approval flow, `SLOOSH_LEASE` escape hatch, idle timeout (docs/internals/architecture.md).
//!
//! Two kinds of state, both in-memory only (a daemon restart means every
//! pending request and active lease is gone — re-approve; this is documented
//! intended behavior, not a bug):
//!
//! - **Pending requests**: created by `sloosh request <host>...`, waiting
//!   for a human to run `sloosh approve <id>` in another terminal. Expire
//!   after [`PENDING_EXPIRY`].
//! - **Active leases**: created by `approve`, binding a set of hosts to an
//!   "anchor" process (docs/internals/architecture.md's ancestry-anchoring scheme) so the
//!   agent process (and anything it spawns) can keep making requests without
//!   re-approval, until the configured vault timeout of no matching calls.
//!
//! Anchor **selection** (choosing which process in the caller's ancestry
//! chain to bind the lease to) happens once, at `request` time. Anchor
//! **matching** (deciding whether some *other*, later call is covered by an
//! already-active lease) never re-runs selection — it just checks whether
//! the stored anchor (a specific `(pid, start_time)` pair) appears anywhere
//! in the caller's current chain, so descendants spawned after approval
//! (e.g. subagents) inherit the lease automatically.

use crate::daemon::audit;
use crate::daemon::ssh;
use crate::daemon::vault::{self, VaultError};
use crate::procs::{self, AncestorInfo};
use crate::proto::{LeaseActivatedInfo, LeaseRequestSummary, LeaseSummary};
#[cfg(not(test))]
use crate::vault_settings::{VaultSettingsStore, VaultTimeout};
use rand::RngCore;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Mutex as AsyncMutex;

/// Default lease idle timeout when no shared vault setting has been saved.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Hard ceiling for an approved lease, even while actively used. A fresh
/// human approval is required after this point so long-lived forwards and
/// busy automation cannot keep credentials authorized indefinitely.
pub const MAX_LIFETIME: Duration = Duration::from_secs(8 * 60 * 60);

/// How often the background expiry sweep prunes leases and, when the last
/// one expires, clears the cached vault key.
const EXPIRY_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// A pending (unapproved) request older than this is dropped and must be
/// re-requested (`SECURITY.md`).
const PENDING_EXPIRY: Duration = Duration::from_secs(15 * 60);

/// Length (in characters) of generated request IDs.
const REQUEST_ID_LEN: usize = 8;

/// How many wrong-master-password `approve` attempts a pending request
/// survives before being dropped (it must then be re-`request`ed).
const MAX_APPROVE_ATTEMPTS: u32 = 5;

/// Executable basenames treated as "just a shell wrapper, not a meaningful
/// anchor" during anchor selection.
const SHELL_BASENAMES: &[&str] = &["sh", "bash", "zsh", "fish", "dash", "ksh"];
const SLOOSH_BASENAME: &str = "sloosh";

// ---------------------------------------------------------------------
// Errors — self-teaching per docs/internals/architecture.md.
// ---------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error(
        "no pending request '{0}' — it may have already been approved, expired (pending \
         requests expire after 15 minutes), or the ID was mistyped; run `sloosh request \
         <host>...` again to get a fresh one"
    )]
    NoSuchRequest(String),

    #[error(
        "a lease request must name at least one host (e.g. `sloosh request web-prod`) — an \
         empty host list would create a pending request that grants nothing"
    )]
    NoHostsRequested,

    #[error(
        "could not determine the caller's process identity (its process-ancestry chain could \
         not be read), so there is nothing to anchor a lease to — have your user run `sloosh \
         request`/`sloosh approve` from their own terminal and pass the printed \
         SLOOSH_LEASE=<token> explicitly in this process's environment instead"
    )]
    NoAnchor,

    #[error(
        "no credential vault exists yet, so nothing can be approved: approving means proving \
         you are the human who set the master password, and there isn't one to check against. \
         Letting `approve` create the vault here would let any local process pick its own \
         password and approve its own requests. A human must first run `sloosh vault init` in \
         a real terminal to create the vault and set the master password, then re-run `sloosh \
         approve <ID>`"
    )]
    VaultRequired,

    #[error(
        "approval must come from a separate terminal, not from the requesting agent's own \
         process tree — the process this request is anchored to (pid {anchor_pid}) is an \
         ancestor of the process running `approve`. Ask your user to run `sloosh approve \
         {id}` themselves, in their own terminal"
    )]
    SelfApproval { id: String, anchor_pid: u32 },

    #[error(
        "wrong master password — the request is still pending; run `sloosh approve <ID>` \
         again ({remaining} attempt(s) left before the request is dropped). There is no \
         recovery if the password is forgotten, other than deleting ~/.sloosh/vault and \
         re-adding your hosts"
    )]
    WrongPassword { remaining: u32 },

    #[error(
        "wrong master password {attempts} times in a row — this pending request has been \
         dropped as a precaution; run `sloosh request <host>...` again to get a fresh ID"
    )]
    TooManyFailedAttempts { attempts: u32 },

    #[error(
        "the host list changed after vault unlock, so this approval was not activated. You \
         confirmed [{approved}], but the daemon independently resolved [{resolved}]. The \
         request is still pending; inspect the full list and run `sloosh approve {id}` again"
    )]
    ApprovedHostsMismatch {
        id: String,
        approved: String,
        resolved: String,
    },

    #[error(transparent)]
    Route(#[from] ssh::SshError),

    #[error(transparent)]
    Vault(#[from] VaultError),
}

// ---------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------

/// A specific process identity a lease (or pending request) is bound to.
/// Binding to `(pid, start_time)` rather than just `pid` is what makes this
/// safe against PID reuse: see `procs::ancestry_chain`'s guard.
#[derive(Debug, Clone)]
struct Anchor {
    pid: u32,
    start_time: SystemTime,
    name: Option<String>,
}

impl Anchor {
    fn from_ancestor(a: &AncestorInfo) -> Self {
        Anchor {
            pid: a.pid,
            start_time: a.start_time,
            name: procs::pick_display_name(
                a.exe_basename.as_deref(),
                a.exe_path_basename.as_deref(),
                a.argv0_basename.as_deref(),
            ),
        }
    }

    /// Does `a` (some entry in a *current* ancestry chain) refer to the same
    /// process instance this anchor was bound to?
    fn matches(&self, a: &AncestorInfo) -> bool {
        self.pid == a.pid && self.start_time == a.start_time
    }
}

struct PendingRequest {
    hosts: Vec<String>,
    anchor: Anchor,
    created_at: Instant,
    /// Wrong-master-password approval attempts so far. A typo must not force
    /// the agent to re-`request` (the human just tries again), but attempts
    /// are capped at [`MAX_APPROVE_ATTEMPTS`] before the request is dropped.
    failed_attempts: u32,
}

struct ActiveLease {
    anchor: Anchor,
    hosts: HashSet<String>,
    created_at: Instant,
    last_used: Instant,
    /// Escape-hatch token (`SLOOSH_LEASE=...`), shown once in `approve`'s
    /// confirmation output (docs/internals/architecture.md).
    token: String,
}

/// Opaque handle to the exact active lease that authorized one host.
///
/// Long-lived daemon work stores this instead of the short-lived CLI PID.
/// The token never leaves this module, and `host` narrows the handle to the
/// capability resolved when the work was created.
#[derive(Clone)]
pub(crate) struct LeaseGrant {
    token: String,
    host: String,
}

#[cfg(test)]
impl LeaseGrant {
    pub(crate) fn invalid_for_test(host: &str) -> Self {
        Self {
            token: "test-invalid-grant".to_string(),
            host: host.to_string(),
        }
    }
}

#[derive(Default)]
struct LeaseState {
    pending: HashMap<String, PendingRequest>,
    active: Vec<ActiveLease>,
}

fn state() -> &'static AsyncMutex<LeaseState> {
    static STATE: OnceLock<AsyncMutex<LeaseState>> = OnceLock::new();
    STATE.get_or_init(|| AsyncMutex::new(LeaseState::default()))
}

/// Drop stale pending requests plus active leases past either idle or absolute
/// lifetime limits. If the last active lease is dropped, also clear the cached
/// vault key (docs/internals/architecture.md: "the derived key is cached... zeroize + drop when
/// the last lease expires"). API entry points and [`spawn_reaper`] both use
/// this one expiry decision.
async fn prune_expired(st: &mut LeaseState) {
    prune_expired_at(st, Instant::now(), configured_idle_timeout()).await;
}

async fn prune_expired_at(st: &mut LeaseState, now: Instant, idle_timeout: Duration) {
    st.pending
        .retain(|_, p| now.duration_since(p.created_at) < PENDING_EXPIRY);

    let had_active = !st.active.is_empty();
    let (kept, expired): (Vec<ActiveLease>, Vec<ActiveLease>) =
        std::mem::take(&mut st.active).into_iter().partition(|l| {
            now.duration_since(l.last_used) < idle_timeout
                && now.duration_since(l.created_at) < MAX_LIFETIME
        });
    st.active = kept;
    for l in &expired {
        let mut hosts: Vec<String> = l.hosts.iter().cloned().collect();
        hosts.sort();
        audit::record(
            "lease_expired",
            serde_json::json!({
                "hosts": hosts, "anchor_name": l.anchor.name, "anchor_pid": l.anchor.pid,
            }),
        );
    }
    if had_active && st.active.is_empty() {
        vault::clear_cache().await;
    }
}

/// Test-only seam used by the live SFTP suite to cross the real absolute
/// expiry boundary without sleeping for eight hours. This is not compiled by
/// default and is never reachable through the daemon wire protocol.
#[cfg(feature = "integration-test-hooks")]
#[doc(hidden)]
pub async fn expire_active_leases_for_integration_test() {
    let mut st = state().lock().await;
    let future = Instant::now()
        .checked_add(MAX_LIFETIME)
        .expect("an eight-hour monotonic deadline must fit");
    prune_expired_at(&mut st, future, configured_idle_timeout()).await;
}

/// Start an expiry sweep. Unlike lazy pruning at API entry
/// points, this guarantees the cached vault key is cleared after expiry even
/// when the daemon receives no further requests.
pub fn spawn_reaper() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(EXPIRY_SWEEP_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            let mut st = state().lock().await;
            prune_expired(&mut st).await;
        }
    });
}

// ---------------------------------------------------------------------
// Anchor selection (pure, unit-testable — see tests below)
// ---------------------------------------------------------------------

fn is_skippable(name: Option<&str>) -> bool {
    match name {
        Some(n) => n == SLOOSH_BASENAME || SHELL_BASENAMES.contains(&n),
        None => false,
    }
}

/// Pick the anchor from a caller's ancestry chain (`chain[0]` is the caller
/// itself, i.e. the connecting `sloosh` CLI process; `chain[1..]` are its
/// parent, grandparent, etc., per `procs::ancestry_chain`).
///
/// `chain[0]` is unconditionally skipped regardless of whether its name
/// resolves (defense in depth: it is *always* the `sloosh` binary by
/// construction, so treating an unresolved name as fair game would be
/// wrong). From index 1 onward, shells and `sloosh` itself (in case of
/// nested invocations) are skipped by name; an unresolved name at these
/// positions is treated as *not* skippable, since we have no evidence it's
/// safe to skip and anchoring on an ambiguous process is safer than
/// anchoring on none.
///
/// If the entire remaining chain is skippable (e.g. a human running
/// `sloosh` directly from an interactive shell, with nothing above it worth
/// naming), falls back to the topmost skippable entry rather than returning
/// no anchor at all — some identity is more useful than the feature failing
/// outright for that common case.
fn select_anchor(chain: &[AncestorInfo]) -> Option<Anchor> {
    let (first, rest) = chain.split_first()?;
    if rest.is_empty() {
        return Some(Anchor::from_ancestor(first));
    }
    for a in rest {
        if !is_skippable(a.exe_basename.as_deref()) {
            return Some(Anchor::from_ancestor(a));
        }
    }
    rest.last().map(Anchor::from_ancestor)
}

fn chain_contains_anchor(anchor: &Anchor, chain: &[AncestorInfo]) -> bool {
    chain.iter().any(|a| anchor.matches(a))
}

// ---------------------------------------------------------------------
// ID / token generation
// ---------------------------------------------------------------------

/// Crockford base32 (excludes I/L/O/U to avoid visual ambiguity), hand-rolled
/// rather than pulling in a crate for an 8-character random ID.
const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn generate_request_id() -> String {
    let mut raw = [0u8; REQUEST_ID_LEN];
    rand::rng().fill_bytes(&mut raw);
    raw.iter()
        .map(|b| CROCKFORD_ALPHABET[(*b as usize) % CROCKFORD_ALPHABET.len()] as char)
        .collect()
}

fn generate_lease_token() -> String {
    let mut raw = [0u8; 24];
    rand::rng().fill_bytes(&mut raw);
    vault::hex_encode(&raw)
}

// ---------------------------------------------------------------------
// Public API — thin wrappers binding the generic (test-injectable) core to
// the real platform `ProcessTree`.
// ---------------------------------------------------------------------

/// Outcome of `sloosh request`.
#[derive(Debug)]
pub enum RequestOutcome {
    /// An already-active lease (bound to an anchor in the caller's current
    /// ancestry) already covers every requested host — docs/internals/architecture.md's
    /// idempotency guarantee. No human action needed.
    AlreadyAuthorized,
    /// A new pending request was created; a human needs to `approve` it.
    Pending(LeaseRequestSummary),
}

pub async fn request_lease(
    caller_pid: u32,
    hosts: Vec<String>,
) -> Result<RequestOutcome, LeaseError> {
    request_lease_for_chain(
        procs::ancestry_chain::<procs::ProcessTree>(caller_pid),
        hosts,
    )
    .await
}

/// Core of [`request_lease`], taking the caller's already-walked ancestry
/// chain — the seam unit tests use to exercise the state machine with
/// synthetic chains.
async fn request_lease_for_chain(
    chain: Vec<AncestorInfo>,
    hosts: Vec<String>,
) -> Result<RequestOutcome, LeaseError> {
    if hosts.is_empty() {
        return Err(LeaseError::NoHostsRequested);
    }

    let mut st = state().lock().await;
    prune_expired(&mut st).await;

    let covered: HashSet<&str> = st
        .active
        .iter()
        .filter(|l| chain_contains_anchor(&l.anchor, &chain))
        .flat_map(|l| l.hosts.iter().map(String::as_str))
        .collect();
    if hosts.iter().all(|h| covered.contains(h.as_str())) {
        let now = Instant::now();
        for l in st.active.iter_mut() {
            if chain_contains_anchor(&l.anchor, &chain) {
                l.last_used = now;
            }
        }
        return Ok(RequestOutcome::AlreadyAuthorized);
    }

    // No usable anchor means an unmatchable lease: its anchor would never
    // appear in any later caller's chain, silently granting nothing. Refuse
    // up front instead (the error points at the SLOOSH_LEASE escape hatch).
    let anchor = select_anchor(&chain).ok_or(LeaseError::NoAnchor)?;

    let id = loop {
        let candidate = generate_request_id();
        if !st.pending.contains_key(&candidate) {
            break candidate;
        }
    };
    let vault_exists = vault::exists();
    st.pending.insert(
        id.clone(),
        PendingRequest {
            hosts: hosts.clone(),
            anchor: anchor.clone(),
            created_at: Instant::now(),
            failed_attempts: 0,
        },
    );

    Ok(RequestOutcome::Pending(LeaseRequestSummary {
        id,
        hosts,
        anchor_name: anchor.name,
        anchor_pid: anchor.pid,
        age_secs: 0,
        vault_exists,
    }))
}

/// Fetch details of a still-pending request, for `sloosh approve` to display
/// before prompting for the master password.
pub async fn describe_pending(id: &str) -> Result<LeaseRequestSummary, LeaseError> {
    let mut st = state().lock().await;
    prune_expired(&mut st).await;
    let p = st
        .pending
        .get(id)
        .ok_or_else(|| LeaseError::NoSuchRequest(id.to_string()))?;
    Ok(LeaseRequestSummary {
        id: id.to_string(),
        hosts: p.hosts.clone(),
        anchor_name: p.anchor.name.clone(),
        anchor_pid: p.anchor.pid,
        age_secs: p.created_at.elapsed().as_secs(),
        vault_exists: vault::exists(),
    })
}

/// Approve a pending request: verify the master password by unlocking the
/// vault, populate the vault's in-memory cache, and activate the lease.
/// `approver_pid` is the peer PID of the process running `sloosh approve`,
/// used for the self-approval guard (see [`approve_lease_for_chain`]).
///
/// Never creates the vault. The CLI's TTY guard on `sloosh approve` only
/// protects that one entry point — any same-user process can write raw
/// NDJSON to the socket — so if a missing vault could be created here, an
/// agent could pick its own master password and approve its own request. A
/// missing vault is therefore a hard error pointing at `sloosh vault init`.
pub async fn approve_lease(
    approver_pid: u32,
    id: &str,
    master_password: &[u8],
    approved_hosts: &[String],
) -> Result<LeaseActivatedInfo, LeaseError> {
    approve_lease_for_chain_checked(
        &procs::ancestry_chain::<procs::ProcessTree>(approver_pid),
        id,
        master_password,
        Some(approved_hosts),
        true,
        true,
    )
    .await
}

/// Core of [`approve_lease`], taking the approver's already-walked ancestry
/// chain. Public so integration tests (which need a lease active inside the
/// same process that requested it) can supply a synthetic approver chain;
/// production code always goes through [`approve_lease`].
///
/// A wrong master password does NOT consume the pending request (a typo
/// shouldn't force the agent to re-`request`); after
/// [`MAX_APPROVE_ATTEMPTS`] consecutive failures the request is dropped.
pub async fn approve_lease_for_chain(
    approver_chain: &[AncestorInfo],
    id: &str,
    master_password: &[u8],
) -> Result<LeaseActivatedInfo, LeaseError> {
    approve_lease_for_chain_checked(approver_chain, id, master_password, None, true, true).await
}

/// Unlock and resolve exact host scope before native UI asks for final
/// confirmation. No lease is activated here.
pub async fn preview_native_approval(
    id: &str,
    master_password: &[u8],
) -> Result<Vec<String>, LeaseError> {
    let hosts = {
        let mut st = state().lock().await;
        prune_expired(&mut st).await;
        st.pending
            .get(id)
            .map(|pending| pending.hosts.clone())
            .ok_or_else(|| LeaseError::NoSuchRequest(id.to_string()))?
    };
    if !vault::exists() {
        return Err(LeaseError::VaultRequired);
    }
    match vault::unlock_for_lease(master_password).await {
        Ok(()) => {
            let mut st = state().lock().await;
            prune_expired(&mut st).await;
            st.pending
                .get_mut(id)
                .ok_or_else(|| LeaseError::NoSuchRequest(id.to_string()))?
                .failed_attempts = 0;
        }
        Err(VaultError::WrongPassword) => {
            let mut st = state().lock().await;
            prune_expired(&mut st).await;
            let pending = st
                .pending
                .get_mut(id)
                .ok_or_else(|| LeaseError::NoSuchRequest(id.to_string()))?;
            pending.failed_attempts += 1;
            if pending.failed_attempts >= MAX_APPROVE_ATTEMPTS {
                st.pending.remove(id);
                return Err(LeaseError::TooManyFailedAttempts {
                    attempts: MAX_APPROVE_ATTEMPTS,
                });
            }
            return Err(LeaseError::WrongPassword {
                remaining: MAX_APPROVE_ATTEMPTS - pending.failed_attempts,
            });
        }
        Err(error) => return Err(error.into()),
    }
    Ok(expand_approval_hosts(&hosts).await?)
}

/// Activate after bundled native UI confirms daemon-resolved host scope.
/// Helper is daemon-spawned, so CLI process-ancestry self-approval check does
/// not apply; exact scope comparison and every other lease invariant remain.
pub async fn approve_lease_native(
    id: &str,
    master_password: &[u8],
    approved_hosts: &[String],
) -> Result<LeaseActivatedInfo, LeaseError> {
    approve_lease_for_chain_checked(&[], id, master_password, Some(approved_hosts), false, false)
        .await
}

/// Drop cache populated only for an unsuccessful native preview. Preserve it
/// when another active lease still owns cache lifetime.
pub async fn discard_native_preview() {
    let should_clear = state().lock().await.active.is_empty();
    if should_clear {
        vault::clear_cache().await;
    }
}

/// Approval state machine shared by production and the synthetic-ancestry
/// integration-test seam. Production always supplies `approved_hosts`; the
/// compatibility seam passes `None` so existing live tests can approve the
/// daemon-computed list without emulating an interactive human CLI. Native
/// approval owns its one outer preview cleanup boundary, while terminal
/// approval asks this function to clean its daemon-side cache on failure.
async fn approve_lease_for_chain_checked(
    approver_chain: &[AncestorInfo],
    id: &str,
    master_password: &[u8],
    approved_hosts: Option<&[String]>,
    enforce_self_approval: bool,
    cleanup_failed_preview: bool,
) -> Result<LeaseActivatedInfo, LeaseError> {
    let mut st = state().lock().await;
    prune_expired(&mut st).await;
    let pending = st
        .pending
        .get_mut(id)
        .ok_or_else(|| LeaseError::NoSuchRequest(id.to_string()))?;

    // Defense in depth against self-approval: if the process running
    // `approve` is a descendant of (or is) the very process this request is
    // anchored to, the "out-of-band human" property is violated — a
    // prompt-injected agent driving `approve` itself would land here.
    if enforce_self_approval && chain_contains_anchor(&pending.anchor, approver_chain) {
        return Err(LeaseError::SelfApproval {
            id: id.to_string(),
            anchor_pid: pending.anchor.pid,
        });
    }

    if !vault::exists() {
        return Err(LeaseError::VaultRequired);
    }

    match vault::unlock_for_lease(master_password).await {
        Ok(()) => {
            // A verified password breaks any preceding run of typos even if
            // the approval later fails closed because its host preview is
            // stale and the human must retry the same pending request.
            pending.failed_attempts = 0;
        }
        Err(VaultError::WrongPassword) => {
            pending.failed_attempts += 1;
            if pending.failed_attempts >= MAX_APPROVE_ATTEMPTS {
                st.pending.remove(id);
                return Err(LeaseError::TooManyFailedAttempts {
                    attempts: MAX_APPROVE_ATTEMPTS,
                });
            }
            let remaining = MAX_APPROVE_ATTEMPTS - pending.failed_attempts;
            return Err(LeaseError::WrongPassword { remaining });
        }
        Err(e) => return Err(e.into()),
    }

    // The request may have been created while the vault was locked, so its
    // vault-backed ProxyJump hops were invisible then. Recompute now, from
    // the daemon's freshly unlocked cache, and compare against the exact
    // list the human confirmed in the separate CLI process. Any config or
    // vault change between preview and activation fails closed and leaves
    // the pending request intact.
    let resolved_hosts = match expand_approval_hosts(&pending.hosts).await {
        Ok(hosts) => hosts,
        Err(error) => {
            if cleanup_failed_preview && st.active.is_empty() {
                vault::clear_cache().await;
            }
            return Err(error.into());
        }
    };
    if let Some(approved_hosts) = approved_hosts {
        if approved_hosts != resolved_hosts {
            let approved = format_host_list(approved_hosts);
            let resolved = format_host_list(&resolved_hosts);
            let clear_cache = cleanup_failed_preview && st.active.is_empty();
            if clear_cache {
                vault::clear_cache().await;
            }
            return Err(LeaseError::ApprovedHostsMismatch {
                id: id.to_string(),
                approved,
                resolved,
            });
        }
    }

    let pending = st
        .pending
        .remove(id)
        .expect("still present: the state lock is held continuously since get_mut");

    let token = generate_lease_token();
    let hosts_set: HashSet<String> = resolved_hosts.iter().cloned().collect();
    st.active.push(ActiveLease {
        anchor: pending.anchor.clone(),
        hosts: hosts_set,
        created_at: Instant::now(),
        last_used: Instant::now(),
        token: token.clone(),
    });

    Ok(LeaseActivatedInfo {
        hosts: resolved_hosts,
        anchor_name: pending.anchor.name,
        anchor_pid: pending.anchor.pid,
        token,
        unverified_hosts: Vec::new(),
    })
}

async fn expand_approval_hosts(hosts: &[String]) -> Result<Vec<String>, ssh::SshError> {
    // Unit tests exercise the lease state machine with synthetic host names
    // and must not consume the developer's real ~/.ssh/config. Integration
    // tests compile the library without cfg(test), so live SSH coverage still
    // uses the production config loader.
    #[cfg(test)]
    let config = ssh::SshConfig::default();
    #[cfg(not(test))]
    let config = ssh::SshConfig::load_default();

    ssh::expand_lease_hosts_with_config(&config, hosts).await
}

fn format_host_list(hosts: &[String]) -> String {
    hosts
        .iter()
        .map(|host| format!("{host:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Is `host` authorized for the caller at `caller_pid`, either via the
/// `SLOOSH_LEASE` escape-hatch token or via ancestry-chain anchor matching?
/// Touches `last_used` on the matching lease if so (docs/internals/architecture.md idle-timeout
/// clock).
pub async fn check_authorized(caller_pid: u32, host: &str, lease_token: Option<&str>) -> bool {
    // The token check never needs the ancestry walk, but doing the walk
    // unconditionally keeps this simple; it's cheap (a handful of sysctls /
    // /proc reads).
    authorized_for_chain(
        &procs::ancestry_chain::<procs::ProcessTree>(caller_pid),
        host,
        lease_token,
        true,
    )
    .await
}

/// Resolve the caller's current authorization to the exact active lease that
/// granted `host`. Long-lived daemon work must retain this grant rather than
/// retaining `caller_pid`, because the CLI process normally exits as soon as
/// the work is created.
pub(crate) async fn resolve_grant(
    caller_pid: u32,
    host: &str,
    lease_token: Option<&str>,
) -> Option<LeaseGrant> {
    resolve_grant_for_chain(
        &procs::ancestry_chain::<procs::ProcessTree>(caller_pid),
        host,
        lease_token,
        true,
    )
    .await
}

/// Revalidate and refresh a previously resolved grant after real use.
pub(crate) async fn check_grant(grant: &LeaseGrant) -> bool {
    grant_is_active(grant, true).await
}

/// Revalidate a previously resolved grant without refreshing its idle clock.
pub(crate) async fn peek_grant(grant: &LeaseGrant) -> bool {
    grant_is_active(grant, false).await
}

/// [`check_authorized`] minus the `last_used` side effect: answers "is this
/// lease still alive?" without keeping it alive. Periodic sweeps (e.g.
/// `forward.rs`'s expiry reaper) MUST use this — polling through the
/// touching variant would refresh the idle clock forever and no lease
/// backing a forward could ever idle out.
pub async fn peek_authorized(caller_pid: u32, host: &str, lease_token: Option<&str>) -> bool {
    authorized_for_chain(
        &procs::ancestry_chain::<procs::ProcessTree>(caller_pid),
        host,
        lease_token,
        false,
    )
    .await
}

/// Core of [`check_authorized`]/[`peek_authorized`], taking the caller's
/// already-walked ancestry chain — the seam unit tests use with synthetic
/// chains. `touch` decides whether a hit refreshes the lease's idle clock.
async fn authorized_for_chain(
    chain: &[AncestorInfo],
    host: &str,
    lease_token: Option<&str>,
    touch: bool,
) -> bool {
    resolve_grant_for_chain(chain, host, lease_token, touch)
        .await
        .is_some()
}

async fn resolve_grant_for_chain(
    chain: &[AncestorInfo],
    host: &str,
    lease_token: Option<&str>,
    touch: bool,
) -> Option<LeaseGrant> {
    let mut st = state().lock().await;
    prune_expired(&mut st).await;

    if let Some(token) = lease_token {
        if let Some(l) = st
            .active
            .iter_mut()
            .find(|l| l.token == token && l.hosts.contains(host))
        {
            if touch {
                l.last_used = Instant::now();
            }
            return Some(LeaseGrant {
                token: l.token.clone(),
                host: host.to_string(),
            });
        }
    }

    if let Some(l) = st
        .active
        .iter_mut()
        .find(|l| l.hosts.contains(host) && chain_contains_anchor(&l.anchor, chain))
    {
        if touch {
            l.last_used = Instant::now();
        }
        return Some(LeaseGrant {
            token: l.token.clone(),
            host: host.to_string(),
        });
    }
    None
}

async fn grant_is_active(grant: &LeaseGrant, touch: bool) -> bool {
    let mut st = state().lock().await;
    prune_expired(&mut st).await;

    let Some(l) = st
        .active
        .iter_mut()
        .find(|l| l.token == grant.token && l.hosts.contains(&grant.host))
    else {
        return false;
    };
    if touch {
        l.last_used = Instant::now();
    }
    true
}

/// Summaries of all active leases, for `status`.
pub async fn list_summaries() -> Vec<LeaseSummary> {
    let mut st = state().lock().await;
    prune_expired(&mut st).await;
    let now = Instant::now();
    let idle_timeout = configured_idle_timeout();
    let mut out: Vec<LeaseSummary> = st
        .active
        .iter()
        .map(|l| {
            let idle = now.duration_since(l.last_used);
            let age = now.duration_since(l.created_at);
            let mut hosts: Vec<String> = l.hosts.iter().cloned().collect();
            hosts.sort();
            LeaseSummary {
                hosts,
                anchor_name: l.anchor.name.clone(),
                anchor_pid: l.anchor.pid,
                idle_remaining_secs: idle_timeout
                    .saturating_sub(idle)
                    .min(MAX_LIFETIME.saturating_sub(age))
                    .as_secs(),
            }
        })
        .collect();
    out.sort_by_key(|a| a.anchor_pid);
    out
}

#[cfg(not(test))]
fn configured_idle_timeout() -> Duration {
    VaultSettingsStore::current_user()
        .load()
        .unwrap_or_else(|_| VaultTimeout::minimum())
        .duration()
}

#[cfg(test)]
fn configured_idle_timeout() -> Duration {
    DEFAULT_IDLE_TIMEOUT
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- anchor selection: pure function, synthetic chains -----------------

    fn ancestor(pid: u32, secs: u64, name: Option<&str>) -> AncestorInfo {
        AncestorInfo {
            pid,
            start_time: SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
            exe_basename: name.map(str::to_string),
            exe_path_basename: None,
            argv0_basename: None,
        }
    }

    #[test]
    fn selects_deepest_non_shell_non_sloosh_ancestor() {
        // claude (agent) -> zsh -c -> sloosh (the caller, chain[0]).
        let chain = vec![
            ancestor(3, 110, Some("sloosh")),
            ancestor(2, 105, Some("zsh")),
            ancestor(1, 100, Some("claude")),
        ];
        let anchor = select_anchor(&chain).expect("should find an anchor");
        assert_eq!(anchor.pid, 1);
        assert_eq!(anchor.name.as_deref(), Some("claude"));
    }

    #[test]
    fn falls_back_to_topmost_shell_when_nothing_else_available() {
        // A human running `sloosh` directly from an interactive shell: the
        // whole remaining chain above the caller is just the shell.
        let chain = vec![
            ancestor(2, 105, Some("sloosh")),
            ancestor(1, 100, Some("zsh")),
        ];
        let anchor = select_anchor(&chain).expect("should still find an anchor");
        assert_eq!(anchor.pid, 1);
        assert_eq!(anchor.name.as_deref(), Some("zsh"));
    }

    #[test]
    fn caller_itself_is_always_skipped_even_with_unresolved_name() {
        // chain[0]'s name failed to resolve (None) -- must still be skipped
        // unconditionally, not treated as a valid anchor just because the
        // name-based filter can't positively identify it as sloosh/a shell.
        let chain = vec![ancestor(2, 105, None), ancestor(1, 100, Some("claude"))];
        let anchor = select_anchor(&chain).expect("should find an anchor");
        assert_eq!(anchor.pid, 1);
    }

    #[test]
    fn unresolved_name_above_caller_is_not_skipped() {
        // An ancestor above the caller whose name failed to resolve is
        // treated conservatively as a valid (non-skippable) anchor, since we
        // have no evidence it's safe to skip past.
        let chain = vec![
            ancestor(3, 110, Some("sloosh")),
            ancestor(2, 105, None),
            ancestor(1, 100, Some("claude")),
        ];
        let anchor = select_anchor(&chain).expect("should find an anchor");
        assert_eq!(anchor.pid, 2);
    }

    #[test]
    fn only_caller_in_chain_anchors_to_itself() {
        let chain = vec![ancestor(1, 100, Some("sloosh"))];
        let anchor = select_anchor(&chain).expect("should anchor to the lone entry");
        assert_eq!(anchor.pid, 1);
    }

    #[test]
    fn empty_chain_has_no_anchor() {
        assert!(select_anchor(&[]).is_none());
    }

    #[test]
    fn chain_contains_anchor_requires_both_pid_and_start_time() {
        let anchor = Anchor {
            pid: 42,
            start_time: SystemTime::UNIX_EPOCH + Duration::from_secs(100),
            name: Some("claude".to_string()),
        };
        let matching_chain = vec![ancestor(42, 100, Some("claude"))];
        assert!(chain_contains_anchor(&anchor, &matching_chain));

        // Same pid, different start time: a PID-reuse case must NOT match.
        let reused_pid_chain = vec![ancestor(42, 999, Some("someone-else"))];
        assert!(!chain_contains_anchor(&anchor, &reused_pid_chain));
    }

    // -- lease-level behavior: exercise the internal state machine directly
    //    with hand-built ancestry chains (covers everything
    //    `request_lease_with`/`check_authorized_with` do *except* the actual
    //    `procs::ancestry_chain` walk, which `procs::tests` already covers
    //    in isolation). ----------------------------------------------------

    /// The touching variant under its historical test-facing name: most
    /// lease-level tests below only care about the yes/no answer, and the
    /// production callers they model all touch.
    async fn check_authorized_for_chain(
        chain: &[AncestorInfo],
        host: &str,
        lease_token: Option<&str>,
    ) -> bool {
        authorized_for_chain(chain, host, lease_token, true).await
    }

    /// An approver ancestry chain guaranteed disjoint from every anchor used
    /// in these tests — the synthetic equivalent of the human running
    /// `sloosh approve` in a genuinely separate terminal.
    fn approver_chain() -> Vec<AncestorInfo> {
        vec![
            ancestor(9001, 9000, Some("sloosh")),
            ancestor(9000, 8999, Some("zsh")),
        ]
    }

    /// `approve_lease` never creates the vault (that's the point of the
    /// self-approval fix) — tests that approve must first create one the way
    /// `sloosh vault init` would.
    fn create_test_vault(password: &[u8]) {
        vault::create(&vault::VaultData::default(), password).expect("create test vault");
    }

    fn test_vault_entry(jump: &str) -> vault::HostEntry {
        vault::HostEntry {
            hostname: "web.example.test".to_string(),
            port: Some(22),
            user: Some("deploy".to_string()),
            auth: vault::AuthMethod::Password {
                password: "ssh-secret".to_string(),
            },
            route: crate::proto::HostRoute::ProxyJump {
                spec: jump.to_string(),
            },
        }
    }

    fn create_test_vault_with_jump(password: &[u8], jump: &str) {
        let mut data = vault::VaultData::default();
        data.hosts.insert("web".to_string(), test_vault_entry(jump));
        vault::create(&data, password).expect("create test vault with jump host");
    }

    fn create_test_vault_with_jump_cycle(password: &[u8]) {
        let mut data = vault::VaultData::default();
        data.hosts
            .insert("web".to_string(), test_vault_entry("bastion"));
        data.hosts
            .insert("bastion".to_string(), test_vault_entry("web"));
        vault::create(&data, password).expect("create test vault with jump cycle");
    }

    fn create_test_vault_with_deep_jump_chain(password: &[u8]) {
        const OVER_DEPTH_HOPS: usize = 9;

        let mut data = vault::VaultData::default();
        data.hosts.insert(
            "web".to_string(),
            test_vault_entry("sloosh-test-depth-hop-0"),
        );
        for index in 0..OVER_DEPTH_HOPS {
            let alias = format!("sloosh-test-depth-hop-{index}");
            let mut entry = if index + 1 < OVER_DEPTH_HOPS {
                test_vault_entry(&format!("sloosh-test-depth-hop-{}", index + 1))
            } else {
                test_vault_entry("")
            };
            if index + 1 == OVER_DEPTH_HOPS {
                entry.route = crate::proto::HostRoute::Direct;
            }
            data.hosts.insert(alias, entry);
        }
        vault::create(&data, password).expect("create test vault with deep jump chain");
    }

    /// Each `#[tokio::test]` gets its own OS thread by default, but they all
    /// share the one process-wide `state()` mutex — so these tests run
    /// serially against each other via a dedicated lock to avoid
    /// cross-contamination (there's no per-test daemon instance to isolate
    /// against, unlike `vault.rs`'s file-path-parameterized tests). This
    /// reuses `vault::cache_test_lock()` rather than a lock private to this
    /// module: these tests also drive the process-global vault cache
    /// (`approve_lease` → `vault::unlock_for_lease`, plus the direct
    /// `vault::is_cached`/`clear_cache` calls below), which `vault.rs`'s own
    /// `cache_lifecycle_and_password_reverification` test exercises too —
    /// they all need to serialize against each other, not just within this
    /// module.
    fn test_lock() -> &'static tokio::sync::Mutex<()> {
        vault::cache_test_lock()
    }

    /// These tests exercise `approve_lease`, which goes through the real
    /// `vault::create`/`vault::unlock_for_lease` public API (there's no
    /// lease-level seam to inject a temp path the way `vault.rs`'s own tests
    /// do) — so without this, every test in this module would read and
    /// write the *same* on-disk vault, at the real default location
    /// (`$SLOOSH_HOME`/`~/.sloosh/vault`), and different tests intentionally
    /// use different master passwords, which would collide as soon as more
    /// than one test in this process ever created the vault. Point
    /// `$SLOOSH_HOME` at a private per-process temp directory once, so nothing
    /// here ever touches a real developer's vault.
    fn ensure_isolated_vault_home() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let dir =
                std::env::temp_dir().join(format!("sloosh-lease-test-home-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("create isolated test SLOOSH_HOME");
            // SAFETY: `$SLOOSH_HOME` is process-global, but this only ever
            // runs once (via `std::sync::Once`) before any test in this
            // module touches the vault, and all of those tests additionally
            // serialize against each other via `test_lock()`, so there's no
            // concurrent reader/writer of the environment at the time this
            // runs.
            unsafe {
                std::env::set_var("SLOOSH_HOME", &dir);
            }
        });
    }

    async fn reset_state() {
        ensure_isolated_vault_home();
        // Start every test with no vault at all, so each is free to pick
        // whatever master password it likes without colliding with a vault
        // some earlier test in this process created.
        let _ = std::fs::remove_file(vault::vault_path());
        vault::clear_cache().await;
        let mut st = state().lock().await;
        st.pending.clear();
        st.active.clear();
    }

    #[tokio::test]
    async fn request_then_approve_then_check_authorized_hits() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        let chain = vec![
            ancestor(100, 110, Some("sloosh")),
            ancestor(99, 100, Some("claude")),
        ];
        let outcome = request_lease_for_chain(chain.clone(), vec!["web".to_string()])
            .await
            .unwrap();
        let RequestOutcome::Pending(info) = outcome else {
            panic!("expected a pending request");
        };
        assert_eq!(info.anchor_pid, 99);
        assert_eq!(info.hosts, vec!["web".to_string()]);

        create_test_vault(b"a fresh master password");
        let activated =
            approve_lease_for_chain(&approver_chain(), &info.id, b"a fresh master password")
                .await
                .unwrap();
        assert_eq!(activated.anchor_pid, 99);
        assert_eq!(activated.hosts, vec!["web".to_string()]);
        assert!(!activated.token.is_empty());

        assert!(check_authorized_for_chain(&chain, "web", None).await);
        assert!(!check_authorized_for_chain(&chain, "other-host", None).await);

        // A descendant process spawned later under the same anchor (pid 99)
        // inherits the lease without needing to be the selected anchor.
        let descendant_chain = vec![
            ancestor(101, 120, Some("sloosh")),
            ancestor(102, 115, Some("some-subagent")),
            ancestor(99, 100, Some("claude")),
        ];
        assert!(check_authorized_for_chain(&descendant_chain, "web", None).await);

        reset_state().await;
    }

    /// The forward-expiry reaper polls leases periodically; if that poll
    /// touched `last_used`, no lease backing a forward could ever idle out.
    #[tokio::test]
    async fn peek_answers_without_refreshing_the_idle_clock() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        let chain = vec![
            ancestor(300, 310, Some("sloosh")),
            ancestor(299, 300, Some("claude")),
        ];
        let outcome = request_lease_for_chain(chain.clone(), vec!["web".to_string()])
            .await
            .unwrap();
        let RequestOutcome::Pending(info) = outcome else {
            panic!("expected a pending request");
        };
        create_test_vault(b"a fresh master password");
        approve_lease_for_chain(&approver_chain(), &info.id, b"a fresh master password")
            .await
            .unwrap();

        let before = state().lock().await.active[0].last_used;
        assert!(authorized_for_chain(&chain, "web", None, false).await);
        assert_eq!(state().lock().await.active[0].last_used, before);

        assert!(authorized_for_chain(&chain, "web", None, true).await);
        assert!(state().lock().await.active[0].last_used >= before);

        reset_state().await;
    }

    #[tokio::test]
    async fn resolved_grant_survives_short_lived_caller_exit() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        let caller_chain = vec![
            ancestor(350, 310, Some("sloosh")),
            ancestor(349, 300, Some("claude")),
        ];
        let RequestOutcome::Pending(info) =
            request_lease_for_chain(caller_chain.clone(), vec!["web".to_string()])
                .await
                .unwrap()
        else {
            panic!("expected pending");
        };
        create_test_vault(b"pw");
        approve_lease_for_chain(&approver_chain(), &info.id, b"pw")
            .await
            .unwrap();

        let grant = resolve_grant_for_chain(&caller_chain, "web", None, true)
            .await
            .expect("caller should resolve its active lease to a stable grant");

        // No caller ancestry is consulted here. This models the normal
        // forward lifecycle after the one-shot CLI process has exited.
        assert!(peek_grant(&grant).await);
        assert!(check_grant(&grant).await);

        let wrong_host = LeaseGrant {
            token: grant.token.clone(),
            host: "db".to_string(),
        };
        assert!(!peek_grant(&wrong_host).await);

        reset_state().await;
    }

    #[tokio::test]
    async fn describe_pending_reports_not_found_after_expiry_or_bad_id() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        let err = describe_pending("NOSUCHID").await.unwrap_err();
        assert!(matches!(err, LeaseError::NoSuchRequest(_)));
        let msg = err.to_string();
        assert!(msg.contains("NOSUCHID"));
        assert!(msg.contains("sloosh request"));

        reset_state().await;
    }

    #[tokio::test]
    async fn escape_hatch_token_authorizes_without_matching_ancestry() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        let chain = vec![
            ancestor(200, 110, Some("sloosh")),
            ancestor(199, 100, Some("claude")),
        ];
        let RequestOutcome::Pending(info) =
            request_lease_for_chain(chain.clone(), vec!["db".to_string()])
                .await
                .unwrap()
        else {
            panic!("expected pending");
        };
        create_test_vault(b"pw");
        let activated = approve_lease_for_chain(&approver_chain(), &info.id, b"pw")
            .await
            .unwrap();

        // A completely unrelated ancestry chain fails without the token...
        let unrelated_chain = vec![ancestor(300, 50, Some("something-else"))];
        assert!(!check_authorized_for_chain(&unrelated_chain, "db", None).await);
        // ...but succeeds when the escape-hatch token is presented.
        assert!(check_authorized_for_chain(&unrelated_chain, "db", Some(&activated.token)).await);
        // A token for the wrong host still fails.
        assert!(
            !check_authorized_for_chain(&unrelated_chain, "other", Some(&activated.token)).await
        );

        reset_state().await;
    }

    #[tokio::test]
    async fn idempotent_request_short_circuits_when_already_covered() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        let chain = vec![
            ancestor(400, 110, Some("sloosh")),
            ancestor(399, 100, Some("claude")),
        ];
        let RequestOutcome::Pending(info) =
            request_lease_for_chain(chain.clone(), vec!["web".to_string()])
                .await
                .unwrap()
        else {
            panic!("expected pending");
        };
        create_test_vault(b"pw");
        approve_lease_for_chain(&approver_chain(), &info.id, b"pw")
            .await
            .unwrap();

        // Requesting the same host again from the same anchor's ancestry is
        // immediately authorized, no new pending request created.
        let outcome = request_lease_for_chain(chain.clone(), vec!["web".to_string()])
            .await
            .unwrap();
        assert!(matches!(outcome, RequestOutcome::AlreadyAuthorized));

        // Requesting a host NOT covered yet still creates a new pending
        // request even though this anchor already has one active lease.
        let outcome = request_lease_for_chain(chain, vec!["other-host".to_string()])
            .await
            .unwrap();
        assert!(matches!(outcome, RequestOutcome::Pending(_)));

        reset_state().await;
    }

    #[tokio::test]
    async fn idle_lease_expires_and_clears_vault_cache() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        let chain = vec![
            ancestor(500, 110, Some("sloosh")),
            ancestor(499, 100, Some("claude")),
        ];
        let RequestOutcome::Pending(info) =
            request_lease_for_chain(chain.clone(), vec!["web".to_string()])
                .await
                .unwrap()
        else {
            panic!("expected pending");
        };
        create_test_vault(b"pw");
        approve_lease_for_chain(&approver_chain(), &info.id, b"pw")
            .await
            .unwrap();
        assert!(vault::is_cached().await);

        // Simulate idle expiry directly (waiting out the configured timeout is
        // obviously not something a unit test can do): backdate the lease's
        // `last_used`.
        {
            let mut st = state().lock().await;
            for l in st.active.iter_mut() {
                l.last_used = Instant::now() - DEFAULT_IDLE_TIMEOUT - Duration::from_secs(1);
            }
        }
        assert!(!check_authorized_for_chain(&chain, "web", None).await);
        assert!(
            !vault::is_cached().await,
            "vault cache must be cleared once the last active lease expires"
        );

        reset_state().await;
        vault::clear_cache().await;
    }

    #[tokio::test]
    async fn active_lease_expires_at_absolute_lifetime_cap() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        let chain = vec![
            ancestor(550, 110, Some("sloosh")),
            ancestor(549, 100, Some("claude")),
        ];
        let RequestOutcome::Pending(info) =
            request_lease_for_chain(chain.clone(), vec!["web".to_string()])
                .await
                .unwrap()
        else {
            panic!("expected pending");
        };
        create_test_vault(b"pw");
        approve_lease_for_chain(&approver_chain(), &info.id, b"pw")
            .await
            .unwrap();

        {
            let mut st = state().lock().await;
            st.active[0].created_at = Instant::now() - MAX_LIFETIME - Duration::from_secs(1);
            st.active[0].last_used = Instant::now();
        }

        assert!(!check_authorized_for_chain(&chain, "web", None).await);
        assert!(!vault::is_cached().await);

        reset_state().await;
    }

    #[tokio::test]
    async fn pending_request_expires_after_ttl() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        let chain = vec![
            ancestor(600, 110, Some("sloosh")),
            ancestor(599, 100, Some("claude")),
        ];
        let RequestOutcome::Pending(info) = request_lease_for_chain(chain, vec!["web".to_string()])
            .await
            .unwrap()
        else {
            panic!("expected pending");
        };
        {
            let mut st = state().lock().await;
            if let Some(p) = st.pending.get_mut(&info.id) {
                p.created_at = Instant::now() - PENDING_EXPIRY - Duration::from_secs(1);
            }
        }
        let err = describe_pending(&info.id).await.unwrap_err();
        assert!(matches!(err, LeaseError::NoSuchRequest(_)));

        reset_state().await;
    }

    #[tokio::test]
    async fn approve_never_creates_the_vault() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        let chain = vec![
            ancestor(700, 110, Some("sloosh")),
            ancestor(699, 100, Some("claude")),
        ];
        let RequestOutcome::Pending(info) = request_lease_for_chain(chain, vec!["web".to_string()])
            .await
            .unwrap()
        else {
            panic!("expected pending");
        };

        // With no vault on disk, a raw Approve (any password) must fail —
        // NOT create the vault with an attacker-chosen password and activate
        // the lease (the self-approval vulnerability).
        let err = approve_lease_for_chain(&approver_chain(), &info.id, b"attacker-chosen")
            .await
            .unwrap_err();
        assert!(matches!(err, LeaseError::VaultRequired), "{err}");
        assert!(err.to_string().contains("sloosh vault init"), "{err}");
        assert!(!vault::exists(), "approve must never create the vault");

        // The pending request survives, so once a human runs `vault init`
        // the same ID can still be approved without a fresh `request`.
        create_test_vault(b"human-chosen");
        approve_lease_for_chain(&approver_chain(), &info.id, b"human-chosen")
            .await
            .unwrap();

        reset_state().await;
    }

    #[tokio::test]
    async fn approval_requires_exact_vault_expanded_host_list() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        let chain = vec![
            ancestor(750, 110, Some("sloosh")),
            ancestor(749, 100, Some("claude")),
        ];
        let RequestOutcome::Pending(info) =
            request_lease_for_chain(chain.clone(), vec!["web".to_string()])
                .await
                .unwrap()
        else {
            panic!("expected pending");
        };
        create_test_vault_with_jump(b"pw", "sloosh-test-bastion-before");

        // This is the list a pre-fix CLI showed while the vault was locked.
        // The daemon unlocks independently, discovers `bastion`, and must
        // leave the request pending rather than silently widening approval.
        let stale_approval = vec!["web".to_string()];
        let err = approve_lease_for_chain_checked(
            &approver_chain(),
            &info.id,
            b"pw",
            Some(&stale_approval),
            true,
            true,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, LeaseError::ApprovedHostsMismatch { .. }),
            "{err}"
        );
        assert!(
            err.to_string().contains("sloosh-test-bastion-before"),
            "{err}"
        );
        assert!(describe_pending(&info.id).await.is_ok());
        assert!(!check_authorized_for_chain(&chain, "web", None).await);
        assert!(!vault::is_cached().await);

        // Model the separate CLI's correct local preview, then change the
        // vault before the daemon sees ApproveLease. Exact comparison must
        // catch this TOCTOU and keep the request pending again.
        vault::unlock_for_lease(b"pw").await.unwrap();
        let preview = expand_approval_hosts(&info.hosts).await.unwrap();
        vault::clear_cache().await;
        assert!(preview.iter().any(|h| h == "sloosh-test-bastion-before"));
        vault::add_entry(
            "web",
            test_vault_entry("sloosh-test-bastion-after"),
            b"pw",
            true,
        )
        .await
        .unwrap();

        let err = approve_lease_for_chain_checked(
            &approver_chain(),
            &info.id,
            b"pw",
            Some(&preview),
            true,
            true,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, LeaseError::ApprovedHostsMismatch { .. }),
            "{err}"
        );
        assert!(
            err.to_string().contains("sloosh-test-bastion-after"),
            "{err}"
        );
        assert!(describe_pending(&info.id).await.is_ok());
        assert!(!vault::is_cached().await);

        vault::unlock_for_lease(b"pw").await.unwrap();
        let exact_approval = expand_approval_hosts(&info.hosts).await.unwrap();
        vault::clear_cache().await;
        assert!(
            exact_approval
                .iter()
                .any(|h| h == "sloosh-test-bastion-after")
        );
        let activated = approve_lease_for_chain_checked(
            &approver_chain(),
            &info.id,
            b"pw",
            Some(&exact_approval),
            true,
            true,
        )
        .await
        .unwrap();
        assert_eq!(activated.hosts, exact_approval);
        assert!(check_authorized_for_chain(&chain, "web", None).await);
        assert!(check_authorized_for_chain(&chain, "sloosh-test-bastion-after", None).await);

        reset_state().await;
    }

    #[tokio::test]
    async fn approval_rejects_invalid_vault_route_without_consuming_request() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        let chain = vec![
            ancestor(775, 110, Some("sloosh")),
            ancestor(774, 100, Some("claude")),
        ];
        let RequestOutcome::Pending(info) =
            request_lease_for_chain(chain.clone(), vec!["web".to_string()])
                .await
                .unwrap()
        else {
            panic!("expected pending");
        };
        create_test_vault_with_jump_cycle(b"pw");

        let error = approve_lease_for_chain_checked(
            &approver_chain(),
            &info.id,
            b"pw",
            Some(&["web".to_string()]),
            true,
            true,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(
                error,
                LeaseError::Route(ssh::SshError::ProxyJumpCycle { ref alias }) if alias == "web"
            ),
            "{error}"
        );
        assert!(describe_pending(&info.id).await.is_ok());
        assert!(!check_authorized_for_chain(&chain, "web", None).await);
        assert!(!vault::is_cached().await);

        reset_state().await;
    }

    #[tokio::test]
    async fn approval_rejects_over_depth_route_without_consuming_request() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        let chain = vec![
            ancestor(780, 110, Some("sloosh")),
            ancestor(779, 100, Some("claude")),
        ];
        let RequestOutcome::Pending(info) =
            request_lease_for_chain(chain.clone(), vec!["web".to_string()])
                .await
                .unwrap()
        else {
            panic!("expected pending");
        };
        create_test_vault_with_deep_jump_chain(b"pw");

        let error = approve_lease_for_chain_checked(
            &approver_chain(),
            &info.id,
            b"pw",
            Some(&["web".to_string()]),
            true,
            true,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(
                error,
                LeaseError::Route(ssh::SshError::ProxyJumpTooDeep { limit: 8 })
            ),
            "{error}"
        );
        assert!(describe_pending(&info.id).await.is_ok());
        assert!(!check_authorized_for_chain(&chain, "web", None).await);
        assert!(!vault::is_cached().await);

        reset_state().await;
    }

    #[tokio::test]
    async fn native_approval_defers_failed_preview_cleanup_to_its_outer_owner() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        let RequestOutcome::Pending(info) = request_lease_for_chain(
            vec![
                ancestor(785, 110, Some("sloosh")),
                ancestor(784, 100, Some("claude")),
            ],
            vec!["web".to_string()],
        )
        .await
        .unwrap() else {
            panic!("expected pending");
        };
        create_test_vault_with_jump_cycle(b"pw");

        let error = approve_lease_for_chain_checked(
            &[],
            &info.id,
            b"pw",
            Some(&["web".to_string()]),
            false,
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, LeaseError::Route(_)), "{error}");
        assert!(vault::is_cached().await);
        assert!(describe_pending(&info.id).await.is_ok());

        discard_native_preview().await;
        assert!(!vault::is_cached().await);
        reset_state().await;
    }

    #[tokio::test]
    async fn self_approval_from_the_anchors_own_tree_is_rejected() {
        let _guard = test_lock().lock().await;
        reset_state().await;
        create_test_vault(b"pw");

        let request_chain = vec![
            ancestor(800, 110, Some("sloosh")),
            ancestor(799, 100, Some("claude")),
        ];
        let RequestOutcome::Pending(info) =
            request_lease_for_chain(request_chain, vec!["web".to_string()])
                .await
                .unwrap()
        else {
            panic!("expected pending");
        };
        assert_eq!(info.anchor_pid, 799);

        // The agent (anchor pid 799) driving `sloosh approve` itself: its
        // chain contains the request's anchor and must be rejected, even
        // with the correct master password.
        let self_chain = vec![
            ancestor(801, 120, Some("sloosh")),
            ancestor(799, 100, Some("claude")),
        ];
        let err = approve_lease_for_chain(&self_chain, &info.id, b"pw")
            .await
            .unwrap_err();
        assert!(matches!(err, LeaseError::SelfApproval { .. }), "{err}");
        assert!(err.to_string().contains("separate terminal"), "{err}");

        // The request is NOT consumed: a genuinely separate terminal can
        // still approve it.
        approve_lease_for_chain(&approver_chain(), &info.id, b"pw")
            .await
            .unwrap();

        reset_state().await;
    }

    #[tokio::test]
    async fn wrong_password_keeps_request_until_attempt_cap() {
        let _guard = test_lock().lock().await;
        reset_state().await;
        create_test_vault(b"correct");

        let chain = vec![
            ancestor(900, 110, Some("sloosh")),
            ancestor(899, 100, Some("claude")),
        ];
        let RequestOutcome::Pending(info) =
            request_lease_for_chain(chain.clone(), vec!["web".to_string()])
                .await
                .unwrap()
        else {
            panic!("expected pending");
        };

        // A few typos leave the request pending, with a decreasing counter.
        for i in 1..MAX_APPROVE_ATTEMPTS {
            let err = approve_lease_for_chain(&approver_chain(), &info.id, b"typo")
                .await
                .unwrap_err();
            match err {
                LeaseError::WrongPassword { remaining } => {
                    assert_eq!(remaining, MAX_APPROVE_ATTEMPTS - i);
                }
                other => panic!("expected WrongPassword, got: {other}"),
            }
        }
        // Still pending: the correct password succeeds without re-request.
        approve_lease_for_chain(&approver_chain(), &info.id, b"correct")
            .await
            .unwrap();

        // Second request: exhausting all attempts consumes it.
        let RequestOutcome::Pending(info) = request_lease_for_chain(chain, vec!["db".to_string()])
            .await
            .unwrap()
        else {
            panic!("expected pending");
        };
        for _ in 1..MAX_APPROVE_ATTEMPTS {
            approve_lease_for_chain(&approver_chain(), &info.id, b"typo")
                .await
                .unwrap_err();
        }
        let err = approve_lease_for_chain(&approver_chain(), &info.id, b"typo")
            .await
            .unwrap_err();
        assert!(
            matches!(err, LeaseError::TooManyFailedAttempts { attempts } if attempts == MAX_APPROVE_ATTEMPTS),
            "{err}"
        );
        assert!(err.to_string().contains("5 times"), "{err}");
        // Consumed: even the correct password now reports no such request.
        let err = approve_lease_for_chain(&approver_chain(), &info.id, b"correct")
            .await
            .unwrap_err();
        assert!(matches!(err, LeaseError::NoSuchRequest(_)), "{err}");

        reset_state().await;
    }

    #[tokio::test]
    async fn native_preview_then_activation_preserves_scope_and_authority() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        let chain = vec![
            ancestor(950, 110, Some("sloosh")),
            ancestor(949, 100, Some("claude")),
        ];
        let RequestOutcome::Pending(info) =
            request_lease_for_chain(chain.clone(), vec!["web".to_string()])
                .await
                .unwrap()
        else {
            panic!("expected pending");
        };
        create_test_vault(b"correct");

        let preview = preview_native_approval(&info.id, b"correct").await.unwrap();
        assert_eq!(preview, vec!["web".to_string()]);
        let activated = approve_lease_native(&info.id, b"correct", &preview)
            .await
            .unwrap();
        assert_eq!(activated.hosts, preview);
        assert!(check_authorized_for_chain(&chain, "web", None).await);

        reset_state().await;
    }

    #[tokio::test]
    async fn native_preview_wrong_password_counts_toward_attempt_limit() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        let chain = vec![
            ancestor(960, 110, Some("sloosh")),
            ancestor(959, 100, Some("claude")),
        ];
        let RequestOutcome::Pending(info) = request_lease_for_chain(chain, vec!["web".to_string()])
            .await
            .unwrap()
        else {
            panic!("expected pending");
        };
        create_test_vault(b"correct");

        let err = preview_native_approval(&info.id, b"stale-keychain-password")
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                LeaseError::WrongPassword { remaining }
                    if remaining == MAX_APPROVE_ATTEMPTS - 1
            ),
            "{err}"
        );
        assert_eq!(
            state()
                .lock()
                .await
                .pending
                .get(&info.id)
                .expect("request remains pending")
                .failed_attempts,
            1
        );

        reset_state().await;
    }

    #[tokio::test]
    async fn empty_host_list_is_rejected() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        let chain = vec![
            ancestor(1000, 110, Some("sloosh")),
            ancestor(999, 100, Some("claude")),
        ];
        let err = request_lease_for_chain(chain, Vec::new())
            .await
            .unwrap_err();
        assert!(matches!(err, LeaseError::NoHostsRequested), "{err}");
        assert!(
            state().lock().await.pending.is_empty(),
            "no useless pending request may be created"
        );

        reset_state().await;
    }

    #[tokio::test]
    async fn unanchorable_caller_is_an_error_not_a_dead_lease() {
        let _guard = test_lock().lock().await;
        reset_state().await;

        // An empty ancestry chain (caller identity unreadable) used to fall
        // back to a made-up anchor whose start_time could never match any
        // real process — a lease that silently grants nothing. It must be a
        // proper error pointing at the escape hatch instead.
        let err = request_lease_for_chain(Vec::new(), vec!["web".to_string()])
            .await
            .unwrap_err();
        assert!(matches!(err, LeaseError::NoAnchor), "{err}");
        assert!(err.to_string().contains("SLOOSH_LEASE"), "{err}");

        reset_state().await;
    }

    #[test]
    fn request_id_uses_crockford_alphabet_and_expected_length() {
        let id = generate_request_id();
        assert_eq!(id.len(), REQUEST_ID_LEN);
        assert!(id.chars().all(|c| CROCKFORD_ALPHABET.contains(&(c as u8))));
    }

    #[test]
    fn lease_tokens_are_unique_and_hex() {
        let a = generate_lease_token();
        let b = generate_lease_token();
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a.len(), 48); // 24 bytes -> 48 hex chars
    }
}
