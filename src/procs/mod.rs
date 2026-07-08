//! Process tree introspection (DESIGN.md §4, §8).
//!
//! Lease anchoring walks the caller's process ancestry to find the
//! human-meaningful "anchor" process (e.g. the `claude` agent process, not
//! the `sloosh` CLI binary or an intermediate shell), so subagents and
//! repeated invocations inherit the lease with zero configuration. That
//! walk needs a `parent_pid` + `start_time` (+ executable name) lookup per
//! platform (sysctl on macOS, `/proc` on Linux); this module is the
//! abstraction boundary so no platform branch leaks into `daemon::lease`.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::ProcessTree;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::ProcessTree;

use std::time::SystemTime;

/// Platform-specific process tree queries needed for lease anchoring.
pub trait ProcessInfo {
    /// Parent PID of `pid`, if it exists and is queryable.
    fn parent_pid(pid: u32) -> Option<u32>;

    /// Process start time, used to disambiguate PID reuse when walking the
    /// ancestor chain (DESIGN.md §4: lease binds to (PID, start time)).
    fn start_time(pid: u32) -> Option<SystemTime>;

    /// Basename of the process's executable (e.g. `"claude"`, `"zsh"`),
    /// used by the anchor-selection algorithm in `daemon::lease` to skip
    /// over the `sloosh` CLI itself and intermediate shells.
    fn exe_basename(pid: u32) -> Option<String>;
}

/// One process in a walked ancestry chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AncestorInfo {
    pub pid: u32,
    pub start_time: SystemTime,
    pub exe_basename: Option<String>,
}

/// Walk `pid`'s ancestry (itself first, then parent, grandparent, ...),
/// stopping when:
/// - a parent link can't be resolved (reached the top, or a permission /
///   lookup failure), or
/// - the "parent" claims a start time *after* the child's — a guard
///   against PID reuse: if the OS recycled a PID out from under us mid-walk,
///   the process now sitting at that PID cannot actually be the child's
///   real parent, so we must not trust anything above it.
///
/// Generic over `P: ProcessInfo` so this walking logic is shared between
/// platforms (and is unit-testable with a fake `ProcessInfo` — see the
/// `tests` module below) even though the underlying lookups are not.
pub fn ancestry_chain<P: ProcessInfo>(pid: u32) -> Vec<AncestorInfo> {
    let mut chain = Vec::new();

    let Some(mut current_start) = P::start_time(pid) else {
        return chain;
    };
    let mut current_pid = pid;
    chain.push(AncestorInfo {
        pid: current_pid,
        start_time: current_start,
        exe_basename: P::exe_basename(current_pid),
    });

    loop {
        let Some(parent_pid) = P::parent_pid(current_pid) else {
            break;
        };
        if parent_pid == 0 || parent_pid == current_pid {
            break;
        }
        let Some(parent_start) = P::start_time(parent_pid) else {
            break;
        };
        if parent_start > current_start {
            // PID reuse: whatever is at `parent_pid` now started after our
            // current node did, so it cannot be its real parent.
            break;
        }
        chain.push(AncestorInfo {
            pid: parent_pid,
            start_time: parent_start,
            exe_basename: P::exe_basename(parent_pid),
        });
        current_pid = parent_pid;
        current_start = parent_start;
    }

    chain
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::time::Duration;

    #[derive(Clone)]
    struct FakeProc {
        parent: Option<u32>,
        start: SystemTime,
        exe: String,
    }

    thread_local! {
        static FAKE_TREE: RefCell<HashMap<u32, FakeProc>> = RefCell::new(HashMap::new());
    }

    struct FakeProcessInfo;

    impl ProcessInfo for FakeProcessInfo {
        fn parent_pid(pid: u32) -> Option<u32> {
            FAKE_TREE.with(|t| t.borrow().get(&pid).and_then(|p| p.parent))
        }
        fn start_time(pid: u32) -> Option<SystemTime> {
            FAKE_TREE.with(|t| t.borrow().get(&pid).map(|p| p.start))
        }
        fn exe_basename(pid: u32) -> Option<String> {
            FAKE_TREE.with(|t| t.borrow().get(&pid).map(|p| p.exe.clone()))
        }
    }

    fn set_proc(pid: u32, parent: Option<u32>, start_offset_secs: u64, exe: &str) {
        FAKE_TREE.with(|t| {
            t.borrow_mut().insert(
                pid,
                FakeProc {
                    parent,
                    start: SystemTime::UNIX_EPOCH + Duration::from_secs(start_offset_secs),
                    exe: exe.to_string(),
                },
            );
        });
    }

    #[test]
    fn walks_full_chain_in_order() {
        // claude (1) -> zsh -c (2) -> sloosh (3), started in that order.
        set_proc(1, None, 100, "claude");
        set_proc(2, Some(1), 105, "zsh");
        set_proc(3, Some(2), 110, "sloosh");

        let chain = ancestry_chain::<FakeProcessInfo>(3);
        let pids: Vec<u32> = chain.iter().map(|a| a.pid).collect();
        assert_eq!(pids, vec![3, 2, 1]);
        assert_eq!(chain[0].exe_basename.as_deref(), Some("sloosh"));
        assert_eq!(chain[2].exe_basename.as_deref(), Some("claude"));
    }

    #[test]
    fn stops_when_parent_start_time_is_after_child() {
        // A PID-reuse scenario: pid 11 is recorded as pid 10's parent, but
        // whatever now occupies pid 11 started *after* pid 10 did, so it
        // can't really be the parent anymore.
        set_proc(10, Some(11), 200, "sloosh");
        set_proc(11, None, 500, "unrelated-reused-pid");

        let chain = ancestry_chain::<FakeProcessInfo>(10);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].pid, 10);
    }

    #[test]
    fn stops_when_parent_is_unqueryable() {
        set_proc(20, Some(21), 300, "sloosh");
        // pid 21 deliberately not registered.
        let chain = ancestry_chain::<FakeProcessInfo>(20);
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn returns_empty_when_start_pid_unqueryable() {
        let chain = ancestry_chain::<FakeProcessInfo>(999_999);
        assert!(chain.is_empty());
    }

    #[test]
    fn stops_at_self_parent_loop() {
        set_proc(30, Some(30), 400, "init-like");
        let chain = ancestry_chain::<FakeProcessInfo>(30);
        assert_eq!(chain.len(), 1);
    }
}
