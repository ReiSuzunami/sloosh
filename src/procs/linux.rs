//! Linux process tree introspection via `/proc/<pid>/stat`.
//!
//! Format (see `proc(5)`): a space-separated line whose second field is the
//! command name in parentheses, e.g.:
//!
//! ```text
//! 1234 (bash) S 1000 1234 1234 0 -1 4194304 ... 21886000 ...
//! ```
//!
//! The comm field is the hostile bit: it can itself contain spaces,
//! parentheses, or newlines (it's whatever the process set via
//! `PR_SET_NAME`/`argv[0]`, truncated to 15 bytes, but not otherwise
//! sanitized). The kernel always wraps it in a matching pair of
//! parentheses, so the robust parse is: take everything up to the *first*
//! `(`, then everything up to the *last* `)` is the comm field (nested or
//! literal parens inside it don't confuse this), and the remaining fields
//! after that final `)` are space-separated and positionally fixed.
//!
//! Fields after the comm field, 1-indexed from `pid` (field 1) per
//! `proc(5)`:
//! - field 4: `ppid`
//! - field 22: `starttime` (clock ticks since boot, per `sysconf(_SC_CLK_TCK)`)

use super::ProcessInfo;
use std::fs;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

pub struct ProcessTree;

impl ProcessInfo for ProcessTree {
    fn parent_pid(pid: u32) -> Option<u32> {
        parse_stat(pid).map(|s| s.ppid)
    }

    fn start_time(pid: u32) -> Option<SystemTime> {
        parse_stat(pid).map(|s| s.start_time)
    }

    fn exe_basename(pid: u32) -> Option<String> {
        parse_stat(pid).map(|s| s.comm)
    }

    fn exe_path_basename(pid: u32) -> Option<String> {
        // `/proc/<pid>/exe` is a symlink to the executable's on-disk path —
        // a second, independent name signal from `comm` above (see
        // `procs::pick_display_name`).
        let target = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        target.file_name().map(|n| n.to_string_lossy().into_owned())
    }

    fn argv0_basename(pid: u32) -> Option<String> {
        // `/proc/<pid>/cmdline` is the argument vector, NUL-separated; the
        // first token is argv[0] — the third name signal (see
        // `procs::pick_display_name`), and the one `ps` displays.
        let cmdline = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        let first = cmdline.split(|&b| b == 0).next()?;
        if first.is_empty() {
            return None;
        }
        let arg0 = String::from_utf8_lossy(first);
        // argv[0] may already be a bare name with no slashes ("claude");
        // `Path::file_name` returns such strings unchanged.
        std::path::Path::new(arg0.as_ref())
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
    }
}

struct StatFields {
    ppid: u32,
    start_time: SystemTime,
    comm: String,
}

/// Ticks per second, as reported by the C library (`sysconf(_SC_CLK_TCK)`).
/// Almost universally 100 on Linux, but read it properly rather than
/// hardcoding since it's cheap and this is exactly the kind of assumption
/// that's fine until it silently isn't.
fn clock_ticks_per_sec() -> i64 {
    static TICKS: OnceLock<i64> = OnceLock::new();
    *TICKS.get_or_init(|| {
        // SAFETY: `sysconf` with a well-known, always-valid name constant;
        // no pointers involved. Falls back to the near-universal default
        // of 100 if the call somehow reports a nonpositive value.
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if ticks > 0 { ticks } else { 100 }
    })
}

/// System boot time, cached for the life of the process (it doesn't
/// change). Read from `/proc/stat`'s `btime` line (seconds since epoch).
fn boot_time() -> Option<SystemTime> {
    static BOOT: OnceLock<Option<SystemTime>> = OnceLock::new();
    *BOOT.get_or_init(|| {
        let contents = fs::read_to_string("/proc/stat").ok()?;
        for line in contents.lines() {
            if let Some(rest) = line.strip_prefix("btime ") {
                let secs: u64 = rest.trim().parse().ok()?;
                return Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs));
            }
        }
        None
    })
}

fn parse_stat(pid: u32) -> Option<StatFields> {
    let path = format!("/proc/{pid}/stat");
    let contents = fs::read_to_string(path).ok()?;

    let open_paren = contents.find('(')?;
    let close_paren = contents.rfind(')')?;
    if close_paren <= open_paren {
        return None;
    }
    let comm = contents[open_paren + 1..close_paren].to_string();

    // Everything after "<pid> (<comm>) " is space-separated fields,
    // starting at field 3 (`state`).
    let rest = contents.get(close_paren + 2..)?;
    let fields: Vec<&str> = rest.split_whitespace().collect();

    // `fields[0]` is field 3 (state); field N is `fields[N - 3]`.
    let ppid: u32 = fields.first()?.parse().ok()?; // field 4
    let starttime_ticks: u64 = fields.get(19)?.parse().ok()?; // field 22

    let boot = boot_time()?;
    let ticks_per_sec = clock_ticks_per_sec() as u64;
    let secs_since_boot = starttime_ticks / ticks_per_sec;
    let start_time = boot + Duration::from_secs(secs_since_boot);

    Some(StatFields {
        ppid,
        start_time,
        comm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_pid_resolves() {
        let pid = std::process::id();
        let start = ProcessTree::start_time(pid).expect("start_time for our own pid");
        assert!(start <= SystemTime::now());

        let ppid = ProcessTree::parent_pid(pid);
        assert!(ppid.is_some());

        let comm = ProcessTree::exe_basename(pid).expect("exe_basename for our own pid");
        assert!(!comm.is_empty());
    }

    #[test]
    fn exe_path_basename_resolves_for_self_and_is_nonempty() {
        let pid = std::process::id();
        let name = ProcessTree::exe_path_basename(pid).expect("exe_path_basename for our own pid");
        assert!(!name.is_empty());
    }

    #[test]
    fn argv0_basename_resolves_for_self_and_is_nonempty() {
        let pid = std::process::id();
        let name = ProcessTree::argv0_basename(pid).expect("argv0_basename for our own pid");
        assert!(!name.is_empty());
    }

    #[test]
    fn nonexistent_pid_returns_none() {
        assert!(ProcessTree::start_time(u32::MAX - 1).is_none());
    }

    /// Pure string-parsing tests for the hostile-`comm` cases, runnable on
    /// any OS (they exercise the parsing helper directly against synthetic
    /// `/proc/<pid>/stat`-shaped strings, not the real filesystem).
    fn parse_stat_line(line: &str) -> Option<(u32, u64)> {
        let open_paren = line.find('(')?;
        let close_paren = line.rfind(')')?;
        if close_paren <= open_paren {
            return None;
        }
        let rest = line.get(close_paren + 2..)?;
        let fields: Vec<&str> = rest.split_whitespace().collect();
        let ppid: u32 = fields.first()?.parse().ok()?;
        let starttime: u64 = fields.get(19)?.parse().ok()?;
        Some((ppid, starttime))
    }

    #[test]
    fn parses_comm_with_spaces() {
        let line = "1234 (my cool app) S 1 1234 1234 0 -1 4194304 0 0 0 0 0 0 0 0 0 0 20 0 1 0 999888 0 0 0 0";
        let (ppid, starttime) = parse_stat_line(line).unwrap();
        assert_eq!(ppid, 1);
        assert_eq!(starttime, 999888);
    }

    #[test]
    fn parses_comm_with_parens() {
        let line = "1234 (evil)(name)) S 42 1234 1234 0 -1 4194304 0 0 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0 0 0";
        let (ppid, starttime) = parse_stat_line(line).unwrap();
        assert_eq!(ppid, 42);
        assert_eq!(starttime, 12345);
    }

    #[test]
    fn rejects_malformed_line() {
        assert!(parse_stat_line("no parens here at all").is_none());
        assert!(parse_stat_line("1234 )backwards( S").is_none());
    }
}
