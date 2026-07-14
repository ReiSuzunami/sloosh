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

/// Convert kernel clock ticks since boot without collapsing distinct process
/// instances that started within the same second. Linux lease identity uses
/// this value to defend against PID reuse.
#[cfg(any(target_os = "linux", test))]
fn system_time_from_ticks(
    boot: SystemTime,
    ticks_since_boot: u64,
    ticks_per_sec: u64,
) -> Option<SystemTime> {
    if ticks_per_sec == 0 {
        return None;
    }
    let whole_secs = ticks_since_boot / ticks_per_sec;
    let remaining_ticks = ticks_since_boot % ticks_per_sec;
    let nanos =
        (u128::from(remaining_ticks) * 1_000_000_000_u128 / u128::from(ticks_per_sec)) as u64;
    boot.checked_add(std::time::Duration::from_secs(whole_secs))?
        .checked_add(std::time::Duration::from_nanos(nanos))
}

/// Platform-specific process tree queries needed for lease anchoring.
pub trait ProcessInfo {
    /// Parent PID of `pid`, if it exists and is queryable.
    fn parent_pid(pid: u32) -> Option<u32>;

    /// Process start time, used to disambiguate PID reuse when walking the
    /// ancestor chain (DESIGN.md §4: lease binds to (PID, start time)).
    fn start_time(pid: u32) -> Option<SystemTime>;

    /// Kernel-reported short process name (`p_comm` on macOS,
    /// `/proc/<pid>/comm` on Linux — e.g. `"claude"`, `"zsh"`), used by the
    /// anchor-selection algorithm in `daemon::lease` to skip over the
    /// `sloosh` CLI itself and intermediate shells, and as the primary
    /// source for the anchor's human-facing display name.
    fn exe_basename(pid: u32) -> Option<String>;

    /// Basename of the process's *actual on-disk executable path*
    /// (`proc_pidpath` on macOS, `readlink /proc/<pid>/exe` on Linux) — a
    /// second, independent name signal. Some agent CLIs are packaged so
    /// that the kernel-reported `comm` ends up being a bare version string
    /// (e.g. `"2.1.204"`) rather than the tool's name; `pick_display_name`
    /// below uses this as a fallback for exactly that case. `None` if the
    /// path can't be resolved (e.g. permission denied, or the process has
    /// already exited).
    fn exe_path_basename(pid: u32) -> Option<String>;

    /// Basename of the process's `argv[0]` (`sysctl KERN_PROCARGS2` on
    /// macOS, first NUL-separated token of `/proc/<pid>/cmdline` on Linux)
    /// — a third, independent name signal. Live evidence against a real
    /// agent install showed both `comm` *and* the on-disk executable path
    /// being a bare version string (the exec'd file itself was named
    /// `2.1.204`), while `argv[0]` — what `ps -o comm` displays — carried
    /// the actual tool name (`claude`). `argv[0]` may already be a bare
    /// name with no slashes; basename of that is the name itself. `None`
    /// on any error (e.g. another user's process, or the process exited).
    fn argv0_basename(pid: u32) -> Option<String>;
}

/// One process in a walked ancestry chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AncestorInfo {
    pub pid: u32,
    pub start_time: SystemTime,
    pub exe_basename: Option<String>,
    pub exe_path_basename: Option<String>,
    pub argv0_basename: Option<String>,
}

/// Does `s` look like a bare version string (e.g. `"2.1.204"`, `"10"`)
/// rather than a real program name? Pure and platform-independent so it's
/// directly unit-testable: every character is an ASCII digit or `.`, and
/// there's at least one character.
pub fn looks_like_version_string(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Pick the best human-facing process name from the three signals
/// `ProcessInfo` can offer, in preference order: the kernel-reported
/// `comm`, the resolved executable path's basename, and the `argv[0]`
/// basename. The first signal that is present and does *not* look like a
/// bare version string wins. If every present signal looks version-like
/// (or none are present), fall back to the first present signal in the
/// same order — *some* identity beats none.
///
/// This is the fix for the live-observed bug where an agent CLI's
/// versioned install made both `comm` and the on-disk executable name its
/// literal version number (the exec'd file was named `2.1.204`), so
/// `sloosh status`/lease-approval prompts showed `"2.1.204"` instead of
/// the tool's name — only `argv[0]` (what `ps -o comm` displays) carried
/// the real name.
pub fn pick_display_name(
    comm: Option<&str>,
    exe_path_basename: Option<&str>,
    argv0_basename: Option<&str>,
) -> Option<String> {
    let signals = [comm, exe_path_basename, argv0_basename];
    signals
        .into_iter()
        .flatten()
        .find(|s| !looks_like_version_string(s))
        .or_else(|| signals.into_iter().flatten().next())
        .map(str::to_string)
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
        exe_path_basename: P::exe_path_basename(current_pid),
        argv0_basename: P::argv0_basename(current_pid),
    });

    while let Some(parent_pid) = P::parent_pid(current_pid) {
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
            exe_path_basename: P::exe_path_basename(parent_pid),
            argv0_basename: P::argv0_basename(parent_pid),
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
        fn exe_path_basename(_pid: u32) -> Option<String> {
            // Not exercised by the ancestry-walking tests below; the
            // pick_display_name tests exercise this signal directly instead.
            None
        }
        fn argv0_basename(_pid: u32) -> Option<String> {
            // Same as exe_path_basename above.
            None
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
    fn tick_conversion_preserves_process_start_subseconds() {
        let boot = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let first = system_time_from_ticks(boot, 12_345, 100).unwrap();
        let second = system_time_from_ticks(boot, 12_346, 100).unwrap();

        assert_eq!(
            first,
            boot + Duration::from_secs(123) + Duration::from_millis(450)
        );
        assert_eq!(
            second.duration_since(first).unwrap(),
            Duration::from_millis(10)
        );
        assert!(system_time_from_ticks(boot, 1, 0).is_none());
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

    #[test]
    fn looks_like_version_string_matches_pure_digit_and_dot_strings() {
        assert!(looks_like_version_string("2.1.204"));
        assert!(looks_like_version_string("10"));
        assert!(looks_like_version_string("..."));
        assert!(!looks_like_version_string("claude"));
        assert!(!looks_like_version_string("claude-2.1.204"));
        assert!(!looks_like_version_string("2.1.204-beta"));
        assert!(!looks_like_version_string(""));
    }

    #[test]
    fn pick_display_name_prefers_comm_when_it_looks_like_a_real_name() {
        assert_eq!(
            pick_display_name(Some("claude"), Some("node"), Some("bun")),
            Some("claude".to_string())
        );
        assert_eq!(
            pick_display_name(Some("claude"), None, None),
            Some("claude".to_string())
        );
    }

    #[test]
    fn pick_display_name_falls_back_to_exe_path_basename_when_comm_is_version_like() {
        assert_eq!(
            pick_display_name(Some("2.1.204"), Some("claude"), None),
            Some("claude".to_string())
        );
    }

    #[test]
    fn pick_display_name_falls_back_to_argv0_when_comm_and_exe_path_are_version_like() {
        // The live-observed bug this three-signal design fixes: a versioned
        // agent install where the exec'd file is literally named after the
        // version, so comm AND the on-disk path basename are both
        // "2.1.204" — only argv[0] carries the real tool name.
        assert_eq!(
            pick_display_name(Some("2.1.204"), Some("2.1.204"), Some("claude")),
            Some("claude".to_string())
        );
        // Same but with the middle signal missing entirely.
        assert_eq!(
            pick_display_name(Some("2.1.204"), None, Some("claude")),
            Some("claude".to_string())
        );
    }

    #[test]
    fn pick_display_name_keeps_comm_when_all_signals_are_version_like() {
        assert_eq!(
            pick_display_name(Some("2.1.204"), Some("2.1.204"), Some("2.1")),
            Some("2.1.204".to_string())
        );
    }

    #[test]
    fn pick_display_name_keeps_version_like_comm_when_it_is_the_only_signal() {
        assert_eq!(
            pick_display_name(Some("2.1.204"), None, None),
            Some("2.1.204".to_string())
        );
    }

    #[test]
    fn pick_display_name_falls_back_in_order_when_comm_missing() {
        assert_eq!(
            pick_display_name(None, Some("claude"), Some("other")),
            Some("claude".to_string())
        );
        assert_eq!(
            pick_display_name(None, None, Some("claude")),
            Some("claude".to_string())
        );
        // A version-like exe_path_basename is skipped in favor of a real
        // argv[0] name, but wins as last resort when argv[0] is absent.
        assert_eq!(
            pick_display_name(None, Some("2.1.204"), Some("claude")),
            Some("claude".to_string())
        );
        assert_eq!(
            pick_display_name(None, Some("2.1.204"), None),
            Some("2.1.204".to_string())
        );
    }

    #[test]
    fn pick_display_name_is_none_when_all_signals_are_missing() {
        assert_eq!(pick_display_name(None, None, None), None);
    }
}
