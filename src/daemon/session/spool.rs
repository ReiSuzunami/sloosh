//! Bounded, best-effort PTY output persistence.
//!
//! Spooling must never become command authority: write, accounting, scan, or
//! retention failures stop disk persistence only. The session memory ring and
//! remote command continue independently.

use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, UNIX_EPOCH};

use tracing::{info, warn};

use crate::diagnostics::{WarningAction, warning_occurrence, warning_recovered};
use crate::transport::unix::{ensure_private_dir as ensure_sloosh_private_dir, sloosh_home};

pub(super) const MAX_SPOOL_DIR_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_SPOOL_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_SPOOL_ROOT_BYTES: u64 = 1024 * 1024 * 1024;
const SPOOL_SCAN_RETRY_INTERVAL: Duration = Duration::from_secs(30);
pub(super) const SPOOL_LIMIT_MARKER: &[u8] =
    b"\n[... sloosh spool limit reached; further output was not persisted ...]\n";
pub(super) const MAX_ENCODED_SPOOL_NAME_BYTES: usize = 96;

pub(super) struct SpoolWriter {
    file: std::fs::File,
    pub(super) path: PathBuf,
    limit: u64,
    bytes_written: u64,
    limited: bool,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) ledger: Option<Arc<Mutex<SpoolLedger>>>,
}

impl SpoolWriter {
    fn new_accounted(file: std::fs::File, path: PathBuf, ledger: Arc<Mutex<SpoolLedger>>) -> Self {
        Self {
            file,
            path,
            limit: MAX_SPOOL_FILE_BYTES,
            bytes_written: 0,
            limited: false,
            ledger: Some(ledger),
        }
    }

    #[cfg(test)]
    pub(super) fn with_limit(file: std::fs::File, path: PathBuf, limit: u64) -> Self {
        Self {
            file,
            path,
            limit,
            bytes_written: 0,
            limited: false,
            ledger: None,
        }
    }

    #[cfg(test)]
    pub(super) fn with_accounting(
        file: std::fs::File,
        path: PathBuf,
        limit: u64,
        ledger: Arc<Mutex<SpoolLedger>>,
    ) -> Self {
        Self {
            file,
            path,
            limit,
            bytes_written: 0,
            limited: false,
            ledger: Some(ledger),
        }
    }

    pub(super) fn write_payload(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if self.limited || bytes.is_empty() {
            return Ok(());
        }

        let marker_len = SPOOL_LIMIT_MARKER.len() as u64;
        let payload_limit = self.limit.saturating_sub(marker_len);
        let remaining = payload_limit.saturating_sub(self.bytes_written);
        let planned_payload = remaining.min(bytes.len() as u64);
        let planned_marker = planned_payload < bytes.len() as u64 && self.limit >= marker_len;
        let planned = planned_payload.saturating_add(if planned_marker { marker_len } else { 0 });
        let granted = if let Some(ledger) = &self.ledger {
            lock_spool_ledger(ledger).claim_bytes(&self.path, planned)
        } else {
            planned
        };

        let root_limited = granted < planned;
        let (keep, write_marker) = if root_limited && granted >= marker_len {
            ((granted - marker_len).min(planned_payload), true)
        } else {
            (
                granted.min(planned_payload),
                planned_marker && granted == planned,
            )
        };

        let write_result = (|| {
            if keep > 0 {
                self.file.write_all(&bytes[..keep as usize])?;
            }
            if write_marker {
                self.file.write_all(SPOOL_LIMIT_MARKER)?;
            }
            Ok(())
        })();
        if let Err(error) = write_result {
            self.reconcile_accounting();
            return Err(error);
        }

        self.bytes_written = self
            .bytes_written
            .saturating_add(keep)
            .saturating_add(if write_marker { marker_len } else { 0 });
        if planned_marker || root_limited {
            self.limited = true;
            warn!(
                diagnostic_code = "SPOOL_LIMIT_REACHED",
                per_run_limit_bytes = self.limit,
                root_persistence_unavailable = root_limited,
                "spool persistence limit reached; further output remains in the memory ring only"
            );
        }
        Ok(())
    }

    fn reconcile_accounting(&mut self) {
        let Some(ledger) = &self.ledger else {
            return;
        };
        if let Ok(metadata) = self.file.metadata() {
            self.bytes_written = metadata.len().min(self.limit);
            lock_spool_ledger(ledger).set_actual_bytes(&self.path, metadata.len());
        }
    }
}

impl Drop for SpoolWriter {
    fn drop(&mut self) {
        let _ = self.file.flush();
        self.reconcile_accounting();
        if let Some(ledger) = &self.ledger {
            let mut ledger = lock_spool_ledger(ledger);
            ledger.mark_inactive(&self.path);
            if let Some(dir) = self.path.parent() {
                ledger.enforce_dir_budget(dir);
            }
            ledger.enforce_global_budget();
        } else if let Some(dir) = self.path.parent() {
            cleanup_spool_dir_preserving(dir, Some(&self.path));
        }
    }
}

#[derive(Debug)]
struct SpoolEntry {
    bytes: u64,
    modified: std::time::SystemTime,
    active: bool,
}

#[derive(Debug)]
pub(super) struct SpoolLedger {
    root: PathBuf,
    max_bytes: u64,
    pub(super) initialized: bool,
    pub(super) next_scan_attempt: Option<Instant>,
    pub(super) total_bytes: u64,
    entries: HashMap<PathBuf, SpoolEntry>,
    #[cfg(test)]
    pub(super) scan_count: usize,
}

impl SpoolLedger {
    pub(super) fn new(root: PathBuf, max_bytes: u64) -> Self {
        Self {
            root,
            max_bytes,
            initialized: false,
            next_scan_attempt: None,
            total_bytes: 0,
            entries: HashMap::new(),
            #[cfg(test)]
            scan_count: 0,
        }
    }

    pub(super) fn initialize(&mut self) {
        if self.initialized {
            return;
        }
        if self
            .next_scan_attempt
            .is_some_and(|deadline| deadline > Instant::now())
        {
            return;
        }
        #[cfg(test)]
        {
            self.scan_count += 1;
        }

        let (mut entries, mut total_bytes) = match scan_spool_root(&self.root) {
            Ok(snapshot) => {
                if let Some(suppressed) = warning_recovered("SPOOL_INDEX_FAILED", &self.root) {
                    info!(
                        diagnostic_code = "SPOOL_INDEX_RECOVERED",
                        suppressed, "spool root indexing recovered"
                    );
                }
                snapshot
            }
            Err(error) => {
                self.next_scan_attempt = Some(Instant::now() + SPOOL_SCAN_RETRY_INTERVAL);
                if let WarningAction::Emit { suppressed } =
                    warning_occurrence("SPOOL_INDEX_FAILED", &self.root)
                {
                    warn!(
                        diagnostic_code = "SPOOL_INDEX_FAILED",
                        error_kind = ?error.kind(),
                        suppressed,
                        "could not completely index spool root; disk persistence is paused until \
                         a later retry"
                    );
                }
                return;
            }
        };

        for (path, active) in self.entries.iter().filter(|(_, entry)| entry.active) {
            if let Some(scanned) = entries.remove(path) {
                total_bytes = total_bytes.saturating_sub(scanned.bytes);
            }
            total_bytes = total_bytes.saturating_add(active.bytes);
            entries.insert(
                path.clone(),
                SpoolEntry {
                    bytes: active.bytes,
                    modified: active.modified,
                    active: true,
                },
            );
        }

        self.entries = entries;
        self.total_bytes = total_bytes;
        self.initialized = true;
        self.next_scan_attempt = None;
        self.enforce_global_budget();
    }

    pub(super) fn register_active(&mut self, path: &Path) {
        if let Some(previous) = self.entries.remove(path) {
            self.total_bytes = self.total_bytes.saturating_sub(previous.bytes);
        }
        self.entries.insert(
            path.to_path_buf(),
            SpoolEntry {
                bytes: 0,
                modified: std::time::SystemTime::now(),
                active: true,
            },
        );
    }

    pub(super) fn claim_bytes(&mut self, path: &Path, desired: u64) -> u64 {
        if desired == 0 || !self.initialized {
            return 0;
        }
        let target = self.max_bytes.saturating_sub(desired.min(self.max_bytes));
        self.evict_global_until(target);
        let granted = desired.min(self.max_bytes.saturating_sub(self.total_bytes));
        let entry = self
            .entries
            .entry(path.to_path_buf())
            .or_insert(SpoolEntry {
                bytes: 0,
                modified: std::time::SystemTime::now(),
                active: true,
            });
        entry.bytes = entry.bytes.saturating_add(granted);
        entry.modified = std::time::SystemTime::now();
        self.total_bytes = self.total_bytes.saturating_add(granted);
        granted
    }

    fn set_actual_bytes(&mut self, path: &Path, actual: u64) {
        let Some(entry) = self.entries.get_mut(path) else {
            return;
        };
        self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
        entry.bytes = actual;
        entry.modified = std::time::SystemTime::now();
        self.total_bytes = self.total_bytes.saturating_add(actual);
    }

    fn mark_inactive(&mut self, path: &Path) {
        let mut remove_zero_entry = false;
        if let Some(entry) = self.entries.get_mut(path) {
            entry.active = false;
            entry.modified = std::time::SystemTime::now();
            remove_zero_entry = entry.bytes == 0;
        }
        if remove_zero_entry {
            self.entries.remove(path);
        }
    }

    fn enforce_dir_budget(&mut self, dir: &Path) {
        let mut attempted = HashSet::new();
        loop {
            let total: u64 = self
                .entries
                .iter()
                .filter(|(path, _)| path.parent() == Some(dir))
                .map(|(_, entry)| entry.bytes)
                .sum();
            if total <= MAX_SPOOL_DIR_BYTES || !self.evict_oldest(Some(dir), &mut attempted) {
                break;
            }
        }
    }

    fn enforce_global_budget(&mut self) {
        self.evict_global_until(self.max_bytes);
    }

    fn evict_global_until(&mut self, target: u64) {
        let mut attempted = HashSet::new();
        while self.total_bytes > target {
            if !self.evict_oldest(None, &mut attempted) {
                break;
            }
        }
    }

    fn evict_oldest(&mut self, dir: Option<&Path>, attempted: &mut HashSet<PathBuf>) -> bool {
        let mut candidates: Vec<_> = self
            .entries
            .iter()
            .filter(|(path, entry)| {
                !entry.active
                    && entry.bytes > 0
                    && !attempted.contains(path.as_path())
                    && dir.is_none_or(|candidate| path.parent() == Some(candidate))
            })
            .map(|(path, entry)| (path.clone(), entry.modified))
            .collect();
        candidates.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));

        for (path, _) in candidates {
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    if let Some(suppressed) =
                        warning_recovered("SPOOL_EVICTION_REMOVE_FAILED", &self.root)
                    {
                        info!(
                            diagnostic_code = "SPOOL_EVICTION_REMOVE_RECOVERED",
                            suppressed, "spool budget eviction recovered"
                        );
                    }
                    if let Some(entry) = self.entries.remove(&path) {
                        self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
                    }
                    return true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if let Some(suppressed) =
                        warning_recovered("SPOOL_EVICTION_REMOVE_FAILED", &self.root)
                    {
                        info!(
                            diagnostic_code = "SPOOL_EVICTION_REMOVE_RECOVERED",
                            suppressed, "spool budget eviction recovered"
                        );
                    }
                    if let Some(entry) = self.entries.remove(&path) {
                        self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
                    }
                    return true;
                }
                Err(error) => {
                    attempted.insert(path.clone());
                    if let WarningAction::Emit { suppressed } =
                        warning_occurrence("SPOOL_EVICTION_REMOVE_FAILED", &self.root)
                    {
                        warn!(
                            diagnostic_code = "SPOOL_EVICTION_REMOVE_FAILED",
                            error_kind = ?error.kind(),
                            suppressed,
                            "could not remove old spool file during budget enforcement"
                        );
                    }
                }
            }
        }
        false
    }
}

fn scan_spool_root(root: &Path) -> std::io::Result<(HashMap<PathBuf, SpoolEntry>, u64)> {
    let mut entries = HashMap::new();
    let mut total_bytes = 0_u64;
    for session_dir in std::fs::read_dir(root)? {
        let session_dir = session_dir?;
        if !session_dir.file_type()?.is_dir() {
            continue;
        }
        for file in std::fs::read_dir(session_dir.path())? {
            let file = file?;
            if !file.file_type()?.is_file() {
                continue;
            }
            let metadata = file.metadata()?;
            let bytes = metadata.len();
            if bytes == 0 {
                continue;
            }
            total_bytes = total_bytes.saturating_add(bytes);
            entries.insert(
                file.path(),
                SpoolEntry {
                    bytes,
                    modified: metadata.modified().unwrap_or(UNIX_EPOCH),
                    active: false,
                },
            );
        }
    }
    Ok((entries, total_bytes))
}

type SpoolLedgers = HashMap<PathBuf, Arc<Mutex<SpoolLedger>>>;

fn spool_ledgers() -> &'static Mutex<SpoolLedgers> {
    static LEDGERS: OnceLock<Mutex<SpoolLedgers>> = OnceLock::new();
    LEDGERS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn spool_ledger(root: &Path) -> Arc<Mutex<SpoolLedger>> {
    let mut ledgers = spool_ledgers()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    ledgers
        .entry(root.to_path_buf())
        .or_insert_with(|| {
            Arc::new(Mutex::new(SpoolLedger::new(
                root.to_path_buf(),
                MAX_SPOOL_ROOT_BYTES,
            )))
        })
        .clone()
}

pub(super) fn lock_spool_ledger(
    ledger: &Mutex<SpoolLedger>,
) -> std::sync::MutexGuard<'_, SpoolLedger> {
    ledger
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(super) fn encode_spool_name(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(value.len().min(MAX_ENCODED_SPOOL_NAME_BYTES));
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('~');
            encoded.push(char::from(HEX[(byte >> 4) as usize]));
            encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }
    if encoded.len() <= MAX_ENCODED_SPOOL_NAME_BYTES {
        return encoded;
    }

    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    let suffix = format!("~{:016x}", hasher.finish());
    encoded.truncate(MAX_ENCODED_SPOOL_NAME_BYTES - suffix.len());
    encoded.push_str(&suffix);
    encoded
}

pub(super) fn spool_dir_under(root: &Path, host: &str, name: &str) -> PathBuf {
    root.join(format!(
        "h-{}--s-{}",
        encode_spool_name(host),
        encode_spool_name(name)
    ))
}

pub(super) fn ensure_private_dir(path: &Path) -> std::io::Result<()> {
    ensure_sloosh_private_dir(path).map_err(std::io::Error::other)
}

pub(super) fn open_spool_file_under(
    root: &Path,
    host: &str,
    name: &str,
    seq: u64,
) -> std::io::Result<(PathBuf, SpoolWriter)> {
    ensure_private_dir(root)?;
    let dir = spool_dir_under(root, host, name);
    ensure_private_dir(&dir)?;
    let ledger = spool_ledger(root);
    let mut accounting = lock_spool_ledger(&ledger);
    accounting.initialize();
    let (path, file) = create_spool_file(&dir, seq)?;
    match file.metadata() {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => {
            let _ = std::fs::remove_file(&path);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("spool path '{}' is not a regular file", path.display()),
            ));
        }
        Err(error) => {
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
    }
    if let Err(error) = file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
        let _ = std::fs::remove_file(&path);
        return Err(error);
    }
    accounting.register_active(&path);
    accounting.enforce_dir_budget(&dir);
    accounting.enforce_global_budget();
    drop(accounting);
    let writer = SpoolWriter::new_accounted(file, path.clone(), ledger);
    Ok((path, writer))
}

fn create_spool_file(dir: &Path, seq: u64) -> std::io::Result<(PathBuf, std::fs::File)> {
    const MAX_ATTEMPTS: usize = 16;

    for attempt in 0..MAX_ATTEMPTS {
        let filename = if attempt == 0 {
            format!("{seq:08}.log")
        } else {
            format!("{seq:08}-{:016x}.log", rand::random::<u64>())
        };
        let path = dir.join(filename);
        match std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("could not allocate a unique spool file for run sequence {seq}"),
    ))
}

fn open_spool_file_under_best_effort(
    root: &Path,
    host: &str,
    name: &str,
    seq: u64,
) -> (PathBuf, Option<SpoolWriter>) {
    match open_spool_file_under(root, host, name, seq) {
        Ok((path, writer)) => {
            if let Some(suppressed) = warning_recovered("SPOOL_OPEN_FAILED", &(host, name)) {
                info!(
                    diagnostic_code = "SPOOL_OPEN_RECOVERED",
                    suppressed, "spool file creation recovered"
                );
            }
            (path, Some(writer))
        }
        Err(error) => {
            if let WarningAction::Emit { suppressed } =
                warning_occurrence("SPOOL_OPEN_FAILED", &(host, name))
            {
                warn!(
                    diagnostic_code = "SPOOL_OPEN_FAILED",
                    error_kind = ?error.kind(),
                    suppressed,
                    "spool open failed; command and in-memory output continue"
                );
            }
            (PathBuf::new(), None)
        }
    }
}

pub(super) fn open_spool_file_best_effort(
    host: &str,
    name: &str,
    seq: u64,
) -> (PathBuf, Option<SpoolWriter>) {
    open_spool_file_under_best_effort(&sloosh_home().join("spool"), host, name, seq)
}

pub(super) fn cleanup_spool_dir_preserving(dir: &Path, preserve: Option<&Path>) {
    let mut entries: Vec<(PathBuf, u64, std::time::SystemTime)> = match std::fs::read_dir(dir) {
        Ok(read_dir) => {
            if let Some(suppressed) = warning_recovered("SPOOL_CLEANUP_LIST_FAILED", dir) {
                info!(
                    diagnostic_code = "SPOOL_CLEANUP_LIST_RECOVERED",
                    suppressed, "spool cleanup directory listing recovered"
                );
            }
            read_dir
                .filter_map(Result::ok)
                .filter_map(|entry| {
                    if !entry.file_type().ok()?.is_file() {
                        return None;
                    }
                    let metadata = entry.metadata().ok()?;
                    Some((
                        entry.path(),
                        metadata.len(),
                        metadata.modified().unwrap_or(UNIX_EPOCH),
                    ))
                })
                .collect()
        }
        Err(error) => {
            if let WarningAction::Emit { suppressed } =
                warning_occurrence("SPOOL_CLEANUP_LIST_FAILED", dir)
            {
                warn!(
                    diagnostic_code = "SPOOL_CLEANUP_LIST_FAILED",
                    error_kind = ?error.kind(),
                    suppressed,
                    "could not list spool directory for cleanup"
                );
            }
            return;
        }
    };
    entries.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(&b.0)));
    let mut total: u64 = entries.iter().map(|(_, len, _)| *len).sum();
    for (path, len, _) in &entries {
        if total <= MAX_SPOOL_DIR_BYTES {
            break;
        }
        if preserve.is_some_and(|keep| keep == path) {
            continue;
        }
        match std::fs::remove_file(path) {
            Ok(()) => {
                if let Some(suppressed) = warning_recovered("SPOOL_CLEANUP_REMOVE_FAILED", dir) {
                    info!(
                        diagnostic_code = "SPOOL_CLEANUP_REMOVE_RECOVERED",
                        suppressed, "spool cleanup removal recovered"
                    );
                }
                total = total.saturating_sub(*len);
            }
            Err(error) => {
                if let WarningAction::Emit { suppressed } =
                    warning_occurrence("SPOOL_CLEANUP_REMOVE_FAILED", dir)
                {
                    warn!(
                        diagnostic_code = "SPOOL_CLEANUP_REMOVE_FAILED",
                        error_kind = ?error.kind(),
                        suppressed,
                        "could not remove old spool file"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
pub(super) fn cleanup_spool_root(root: &Path) -> std::io::Result<()> {
    let ledger = spool_ledger(root);
    let mut ledger = lock_spool_ledger(&ledger);
    ledger.initialize();
    ledger.enforce_global_budget();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spool_open_failure_degrades_to_no_persistence() {
        let root = std::env::temp_dir().join(format!(
            "sloosh-spool-open-failure-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&root, b"not a directory").unwrap();

        let (path, writer) = open_spool_file_under_best_effort(&root, "host", "session", 1);

        assert!(path.as_os_str().is_empty());
        assert!(writer.is_none());
        let _ = std::fs::remove_file(root);
    }
}
