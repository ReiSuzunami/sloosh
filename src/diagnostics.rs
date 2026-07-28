//! Bounded, process-local suppression for repeatable operational warnings.
//!
//! Callers keep ownership of message text and redacted fields. This module
//! only decides when to emit and how many equivalent events were suppressed.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher as _};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const WARNING_WINDOW: Duration = Duration::from_secs(60);
const MAX_WARNING_KEYS: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WarningAction {
    Emit { suppressed: u64 },
    Suppress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct WarningKey {
    code: &'static str,
    scope: u64,
}

#[derive(Debug, Clone, Copy)]
struct WarningEntry {
    window_start: Instant,
    suppressed: u64,
}

struct WarningLimiter {
    window: Duration,
    entries: HashMap<WarningKey, WarningEntry>,
}

impl WarningLimiter {
    fn new(window: Duration) -> Self {
        Self {
            window,
            entries: HashMap::new(),
        }
    }

    fn observe_at(&mut self, code: &'static str, scope: u64, now: Instant) -> WarningAction {
        let key = WarningKey { code, scope };
        if let Some(entry) = self.entries.get_mut(&key) {
            if now.saturating_duration_since(entry.window_start) < self.window {
                entry.suppressed = entry.suppressed.saturating_add(1);
                return WarningAction::Suppress;
            }
            let suppressed = entry.suppressed;
            *entry = WarningEntry {
                window_start: now,
                suppressed: 0,
            };
            return WarningAction::Emit { suppressed };
        }

        if self.entries.len() >= MAX_WARNING_KEYS {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.window_start)
                .map(|(key, _)| *key)
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            key,
            WarningEntry {
                window_start: now,
                suppressed: 0,
            },
        );
        WarningAction::Emit { suppressed: 0 }
    }

    fn recover(&mut self, code: &'static str, scope: u64) -> Option<u64> {
        self.entries
            .remove(&WarningKey { code, scope })
            .map(|entry| entry.suppressed)
    }
}

fn limiter() -> &'static Mutex<WarningLimiter> {
    static LIMITER: OnceLock<Mutex<WarningLimiter>> = OnceLock::new();
    LIMITER.get_or_init(|| Mutex::new(WarningLimiter::new(WARNING_WINDOW)))
}

fn hash_scope<T: Hash + ?Sized>(scope: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    scope.hash(&mut hasher);
    hasher.finish()
}

pub(crate) fn warning_occurrence<T: Hash + ?Sized>(code: &'static str, scope: &T) -> WarningAction {
    limiter()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .observe_at(code, hash_scope(scope), Instant::now())
}

pub(crate) fn warning_recovered<T: Hash + ?Sized>(code: &'static str, scope: &T) -> Option<u64> {
    limiter()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .recover(code, hash_scope(scope))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn warning_limiter_emits_first_aggregates_window_and_resets_after_recovery() {
        let mut limiter = WarningLimiter::new(Duration::from_secs(60));
        let start = Instant::now();

        assert_eq!(
            limiter.observe_at("FORWARD_ACCEPT_FAILED", 7, start),
            WarningAction::Emit { suppressed: 0 }
        );
        assert_eq!(
            limiter.observe_at("FORWARD_ACCEPT_FAILED", 7, start + Duration::from_secs(1)),
            WarningAction::Suppress
        );
        assert_eq!(
            limiter.observe_at("FORWARD_ACCEPT_FAILED", 7, start + Duration::from_secs(60)),
            WarningAction::Emit { suppressed: 1 }
        );
        assert_eq!(limiter.recover("FORWARD_ACCEPT_FAILED", 7), Some(0));
        assert_eq!(limiter.recover("FORWARD_ACCEPT_FAILED", 7), None);
        assert_eq!(
            limiter.observe_at("FORWARD_ACCEPT_FAILED", 7, start + Duration::from_secs(61)),
            WarningAction::Emit { suppressed: 0 }
        );
    }

    #[test]
    fn warning_limiter_keeps_bounded_scope_state() {
        let mut limiter = WarningLimiter::new(Duration::from_secs(60));
        let start = Instant::now();

        for scope in 0..=MAX_WARNING_KEYS as u64 {
            let _ = limiter.observe_at("BOUNDED", scope, start);
        }

        assert_eq!(limiter.entries.len(), MAX_WARNING_KEYS);
    }
}
