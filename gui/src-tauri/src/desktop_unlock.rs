use sloosh::proto::SecretString;
use std::fmt;
use std::time::{Duration, Instant};

pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
pub const DEFAULT_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(8 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockMethod {
    MasterPassword,
    TouchId,
    Pin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockStatus {
    Locked,
    Unlocked {
        method: UnlockMethod,
        idle_remaining_secs: u64,
        absolute_remaining_secs: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesktopLocked;

impl fmt::Display for DesktopLocked {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("The credential vault is locked. Unlock it to continue.")
    }
}

struct UnlockedCredential {
    master_password: SecretString,
    method: UnlockMethod,
    unlocked_at: Instant,
    last_used_at: Instant,
}

pub struct DesktopUnlockSession {
    credential: Option<UnlockedCredential>,
    idle_timeout: Duration,
    absolute_timeout: Duration,
}

impl Default for DesktopUnlockSession {
    fn default() -> Self {
        Self::new(DEFAULT_IDLE_TIMEOUT, DEFAULT_ABSOLUTE_TIMEOUT)
    }
}

impl DesktopUnlockSession {
    pub fn new(idle_timeout: Duration, absolute_timeout: Duration) -> Self {
        assert!(idle_timeout > Duration::ZERO);
        assert!(absolute_timeout >= idle_timeout);
        Self {
            credential: None,
            idle_timeout,
            absolute_timeout,
        }
    }

    pub fn unlock(&mut self, master_password: SecretString, method: UnlockMethod) {
        self.unlock_at(master_password, method, Instant::now());
    }

    fn unlock_at(&mut self, master_password: SecretString, method: UnlockMethod, now: Instant) {
        self.credential = Some(UnlockedCredential {
            master_password,
            method,
            unlocked_at: now,
            last_used_at: now,
        });
    }

    pub fn status(&mut self) -> UnlockStatus {
        self.status_at(Instant::now())
    }

    fn status_at(&mut self, now: Instant) -> UnlockStatus {
        if self.is_expired_at(now) {
            self.lock();
            return UnlockStatus::Locked;
        }
        let Some(credential) = self.credential.as_ref() else {
            return UnlockStatus::Locked;
        };
        UnlockStatus::Unlocked {
            method: credential.method,
            idle_remaining_secs: remaining_secs(credential.last_used_at + self.idle_timeout, now),
            absolute_remaining_secs: remaining_secs(
                credential.unlocked_at + self.absolute_timeout,
                now,
            ),
        }
    }

    pub fn credential(&mut self) -> Result<SecretString, DesktopLocked> {
        self.credential_at(Instant::now())
    }

    fn credential_at(&mut self, now: Instant) -> Result<SecretString, DesktopLocked> {
        if self.is_expired_at(now) {
            self.lock();
            return Err(DesktopLocked);
        }
        let credential = self.credential.as_mut().ok_or(DesktopLocked)?;
        credential.last_used_at = now;
        Ok(credential.master_password.clone())
    }

    pub fn touch(&mut self) -> Result<(), DesktopLocked> {
        let now = Instant::now();
        if self.is_expired_at(now) {
            self.lock();
            return Err(DesktopLocked);
        }
        let credential = self.credential.as_mut().ok_or(DesktopLocked)?;
        credential.last_used_at = now;
        Ok(())
    }

    pub fn lock(&mut self) {
        self.credential = None;
    }

    pub fn set_idle_timeout(&mut self, idle_timeout: Duration) {
        self.set_idle_timeout_at(idle_timeout, Instant::now());
    }

    pub fn sync_idle_timeout(&mut self, idle_timeout: Duration) {
        assert!(idle_timeout > Duration::ZERO);
        assert!(idle_timeout <= self.absolute_timeout);
        self.idle_timeout = idle_timeout;
    }

    fn set_idle_timeout_at(&mut self, idle_timeout: Duration, now: Instant) {
        assert!(idle_timeout > Duration::ZERO);
        assert!(idle_timeout <= self.absolute_timeout);
        let credential_expired = self.credential.as_ref().is_some_and(|credential| {
            elapsed(now, credential.last_used_at) >= self.idle_timeout
                || elapsed(now, credential.unlocked_at) >= self.absolute_timeout
        });
        self.idle_timeout = idle_timeout;

        if credential_expired {
            self.lock();
        } else if let Some(credential) = self.credential.as_mut() {
            credential.last_used_at = now;
        }
    }

    fn is_expired_at(&self, now: Instant) -> bool {
        let Some(credential) = self.credential.as_ref() else {
            return false;
        };
        elapsed(now, credential.last_used_at) >= self.idle_timeout
            || elapsed(now, credential.unlocked_at) >= self.absolute_timeout
    }
}

fn elapsed(now: Instant, since: Instant) -> Duration {
    now.checked_duration_since(since).unwrap_or_default()
}

fn remaining_secs(deadline: Instant, now: Instant) -> u64 {
    deadline
        .checked_duration_since(now)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sloosh::proto::SecretString;
    use std::time::{Duration, Instant};

    const IDLE: Duration = Duration::from_secs(15 * 60);
    const ABSOLUTE: Duration = Duration::from_secs(8 * 60 * 60);

    fn session() -> DesktopUnlockSession {
        DesktopUnlockSession::new(IDLE, ABSOLUTE)
    }

    #[test]
    fn unlocked_credential_is_reused_and_activity_extends_idle_deadline() {
        let start = Instant::now();
        let mut session = session();
        session.unlock_at(
            SecretString::new("vault secret"),
            UnlockMethod::MasterPassword,
            start,
        );

        let credential = session
            .credential_at(start + Duration::from_secs(14 * 60))
            .unwrap();
        assert_eq!(credential.expose_secret(), "vault secret");
        assert!(matches!(
            session.status_at(start + Duration::from_secs(28 * 60)),
            UnlockStatus::Unlocked { .. }
        ));
    }

    #[test]
    fn idle_timeout_locks_at_the_deadline() {
        let start = Instant::now();
        let mut session = session();
        session.unlock_at(
            SecretString::new("vault secret"),
            UnlockMethod::TouchId,
            start,
        );

        assert!(matches!(
            session.status_at(start + IDLE),
            UnlockStatus::Locked
        ));
        assert!(session.credential_at(start + IDLE).is_err());
    }

    #[test]
    fn absolute_timeout_wins_even_when_session_is_active() {
        let start = Instant::now();
        let mut session = session();
        session.unlock_at(SecretString::new("vault secret"), UnlockMethod::Pin, start);

        for interval in 1..48 {
            session
                .credential_at(start + Duration::from_secs(interval * 10 * 60))
                .unwrap();
        }
        assert!(matches!(
            session.status_at(start + ABSOLUTE),
            UnlockStatus::Locked
        ));
    }

    #[test]
    fn manual_lock_discards_the_session() {
        let start = Instant::now();
        let mut session = session();
        session.unlock_at(
            SecretString::new("vault secret"),
            UnlockMethod::MasterPassword,
            start,
        );

        session.lock();

        assert!(matches!(session.status_at(start), UnlockStatus::Locked));
        assert!(session.credential_at(start).is_err());
    }

    #[test]
    fn status_reports_method_and_bounded_remaining_time() {
        let start = Instant::now();
        let mut session = session();
        session.unlock_at(
            SecretString::new("vault secret"),
            UnlockMethod::TouchId,
            start,
        );

        assert_eq!(
            session.status_at(start + Duration::from_secs(30)),
            UnlockStatus::Unlocked {
                method: UnlockMethod::TouchId,
                idle_remaining_secs: IDLE.as_secs() - 30,
                absolute_remaining_secs: ABSOLUTE.as_secs() - 30,
            }
        );
    }

    #[test]
    fn changing_timeout_starts_a_new_idle_window() {
        let start = Instant::now();
        let mut session = session();
        session.unlock_at(
            SecretString::new("vault secret"),
            UnlockMethod::MasterPassword,
            start,
        );

        session.set_idle_timeout_at(Duration::from_secs(60), start + Duration::from_secs(61));

        assert!(matches!(
            session.status_at(start + Duration::from_secs(61)),
            UnlockStatus::Unlocked {
                idle_remaining_secs: 60,
                ..
            }
        ));
        assert!(matches!(
            session.status_at(start + Duration::from_secs(121)),
            UnlockStatus::Locked
        ));
    }

    #[test]
    fn changing_timeout_does_not_extend_the_absolute_deadline() {
        let start = Instant::now();
        let mut session = session();
        session.unlock_at(
            SecretString::new("vault secret"),
            UnlockMethod::MasterPassword,
            start,
        );

        session.set_idle_timeout_at(Duration::from_secs(60), start + ABSOLUTE);

        assert!(matches!(
            session.status_at(start + ABSOLUTE),
            UnlockStatus::Locked
        ));
    }

    #[test]
    fn changing_timeout_does_not_revive_an_expired_session() {
        let start = Instant::now();
        let mut session = session();
        session.unlock_at(
            SecretString::new("vault secret"),
            UnlockMethod::MasterPassword,
            start,
        );

        session.set_idle_timeout_at(Duration::from_secs(30 * 60), start + IDLE);

        assert!(matches!(
            session.status_at(start + IDLE),
            UnlockStatus::Locked
        ));
    }

    #[test]
    fn synchronizing_timeout_does_not_refresh_idle_activity() {
        let start = Instant::now();
        let mut session = session();
        session.unlock_at(
            SecretString::new("vault secret"),
            UnlockMethod::MasterPassword,
            start,
        );

        session.sync_idle_timeout(IDLE);

        assert!(matches!(
            session.status_at(start + IDLE),
            UnlockStatus::Locked
        ));
    }
}
