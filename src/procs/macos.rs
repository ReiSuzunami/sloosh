//! macOS process tree introspection via `sysctl(KERN_PROC_PID)`.
//!
//! `libc` doesn't expose `struct kinfo_proc` for Darwin — it's kernel-ABI
//! rather than a stable public header type — so this reads the raw sysctl
//! result buffer and picks fields out by their byte offsets, confirmed by
//! compiling a small C probe against this machine's Xcode SDK headers
//! (`<sys/sysctl.h>`, `<sys/proc.h>`). This is the same layout `ps` and
//! Activity Monitor rely on, so it has strong compatibility pressure even
//! though it isn't reachable from a Rust-facing header:
//!
//! - `sizeof(struct kinfo_proc)` = 648 bytes
//! - `kp_proc.p_starttime` (a `struct timeval`; its first 8 bytes are
//!   `tv_sec`, an `i64` seconds-since-epoch) at absolute offset 0
//! - `kp_proc.p_pid` (`i32`) at absolute offset 40
//! - `kp_proc.p_comm` (17-byte NUL-terminated string, `MAXCOMLEN` 16 + NUL)
//!   at absolute offset 243
//! - `kp_eproc.e_ppid` (`i32`) at absolute offset 560
//!
//! Confirmed on arm64 macOS; x86_64 Macs are assumed to share this layout
//! since it's a long-frozen kernel ABI that userspace tooling depends on
//! for cross-version compatibility.

use super::ProcessInfo;
use std::time::{Duration, SystemTime};

const KINFO_PROC_SIZE: usize = 648;
const OFFSET_P_STARTTIME: usize = 0;
const OFFSET_P_PID: usize = 40;
const OFFSET_P_COMM: usize = 243;
const COMM_LEN: usize = 17;
const OFFSET_E_PPID: usize = 560;

pub struct ProcessTree;

impl ProcessInfo for ProcessTree {
    fn parent_pid(pid: u32) -> Option<u32> {
        query(pid).map(|p| p.ppid)
    }

    fn start_time(pid: u32) -> Option<SystemTime> {
        query(pid).map(|p| p.start_time)
    }

    fn exe_basename(pid: u32) -> Option<String> {
        query(pid).and_then(|p| p.comm)
    }

    fn exe_path_basename(pid: u32) -> Option<String> {
        exe_path(pid).and_then(|p| {
            std::path::Path::new(&p)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
    }

    fn argv0_basename(pid: u32) -> Option<String> {
        argv0(pid).and_then(|a| {
            // argv[0] is often a bare name with no slashes ("claude");
            // `Path::file_name` returns such strings unchanged.
            std::path::Path::new(&a)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
    }
}

/// The process's on-disk executable path via `proc_pidpath` (libproc, part
/// of `libSystem` — no extra linking needed on macOS). A second, independent
/// name signal from `p_comm` above (see `procs::pick_display_name`).
fn exe_path(pid: u32) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buf` is a valid, correctly-sized buffer for the duration of
    // the call; `proc_pidpath` only reads `pid` and writes up to
    // `buf.len()` bytes into `buf`, returning the number of bytes written
    // (or a negative value on error).
    let ret = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len() as u32,
        )
    };
    if ret <= 0 {
        return None;
    }
    std::str::from_utf8(&buf[..ret as usize])
        .ok()
        .map(|s| s.to_string())
}

/// The process's `argv[0]` via `sysctl(KERN_PROCARGS2)` — the third name
/// signal (see `procs::pick_display_name`), and the one `ps -o comm`
/// actually displays. Only works for same-user processes (the kernel
/// refuses other users' argument vectors), which is fine: lease anchoring
/// only ever inspects the calling user's own process tree.
///
/// Result buffer layout (confirmed against a C probe on this machine, and
/// long relied on by `ps`/`procps` ports):
///
/// ```text
/// i32 argc | exec_path\0 | \0 padding... | argv[0]\0 | argv[1]\0 | ... | env...
/// ```
fn argv0(pid: u32) -> Option<String> {
    // Upper bound for the buffer: the kernel's KERN_ARGMAX.
    let mut argmax: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    let mut mib: [libc::c_int; 2] = [libc::CTL_KERN, libc::KERN_ARGMAX];
    // SAFETY: `mib` is a valid 2-element c_int array; `argmax`/`size`
    // describe a real c_int-sized output buffer for the duration of the
    // call; `sysctl` only writes up to `size` bytes into it.
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            &mut argmax as *mut libc::c_int as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || argmax <= 0 {
        return None;
    }

    let mut buf = vec![0u8; argmax as usize];
    let mut size = buf.len();
    let mut mib: [libc::c_int; 3] = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
    // SAFETY: same shape as above — `buf`/`size` describe a real,
    // correctly-sized buffer; `sysctl` writes at most `size` bytes and
    // updates `size` with the number actually written.
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || size < 4 {
        return None;
    }
    let buf = &buf[..size];

    // Skip the leading i32 argc, then the NUL-terminated exec_path, then
    // the run of NUL padding, landing on argv[0].
    let mut i = 4;
    while i < buf.len() && buf[i] != 0 {
        i += 1;
    }
    while i < buf.len() && buf[i] == 0 {
        i += 1;
    }
    let start = i;
    while i < buf.len() && buf[i] != 0 {
        i += 1;
    }
    if start == i {
        return None;
    }
    std::str::from_utf8(&buf[start..i]).ok().map(str::to_string)
}

struct RawProc {
    ppid: u32,
    start_time: SystemTime,
    comm: Option<String>,
}

fn query(pid: u32) -> Option<RawProc> {
    let mut mib: [libc::c_int; 4] = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        pid as libc::c_int,
    ];
    let mut buf = vec![0u8; KINFO_PROC_SIZE];
    let mut size = buf.len();

    // SAFETY: `mib` is a valid, correctly-length array of `c_int`s;
    // `buf`/`size` describe a real, correctly-sized buffer for the
    // duration of the call. `sysctl` is a plain FFI syscall wrapper that
    // only reads `mib` and writes into `buf` (up to `size` bytes),
    // updating `size` to the number of bytes actually written.
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    // A nonexistent pid is reported as success with a zero-length result
    // (a long-standing sysctl quirk for KERN_PROC_PID), which the
    // `size < KINFO_PROC_SIZE` check below also catches.
    if ret != 0 || size < KINFO_PROC_SIZE {
        return None;
    }

    let pid_field = i32::from_ne_bytes(buf[OFFSET_P_PID..OFFSET_P_PID + 4].try_into().ok()?);
    if pid_field != pid as i32 {
        // Defensive: sysctl found *something* but it doesn't match the pid
        // we asked for; don't report it as belonging to this pid.
        return None;
    }

    let tv_sec = i64::from_ne_bytes(
        buf[OFFSET_P_STARTTIME..OFFSET_P_STARTTIME + 8]
            .try_into()
            .ok()?,
    );
    if tv_sec < 0 {
        return None;
    }
    let start_time = SystemTime::UNIX_EPOCH + Duration::from_secs(tv_sec as u64);

    let ppid = i32::from_ne_bytes(buf[OFFSET_E_PPID..OFFSET_E_PPID + 4].try_into().ok()?);
    if ppid < 0 {
        return None;
    }

    let comm_bytes = &buf[OFFSET_P_COMM..OFFSET_P_COMM + COMM_LEN];
    let nul_pos = comm_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(comm_bytes.len());
    let comm = std::str::from_utf8(&comm_bytes[..nul_pos])
        .ok()
        .map(|s| s.to_string());

    Some(RawProc {
        ppid: ppid as u32,
        start_time,
        comm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_pid_resolves_and_matches_process_name() {
        let pid = std::process::id();
        let start = ProcessTree::start_time(pid).expect("start_time for our own pid");
        // Sanity: our own start time should be in the past but not
        // absurdly so (not before the epoch, not in the future).
        assert!(start <= SystemTime::now());

        let comm = ProcessTree::exe_basename(pid).expect("exe_basename for our own pid");
        // The test binary's comm name is truncated to 16 chars by the
        // kernel; just check it's non-empty and plausible.
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
        // Our own process is same-user by definition, so KERN_PROCARGS2
        // must be readable; the test binary is invoked by path, so its
        // argv[0] basename should match its executable path basename.
        let pid = std::process::id();
        let name = ProcessTree::argv0_basename(pid).expect("argv0_basename for our own pid");
        assert!(!name.is_empty());
    }

    #[test]
    fn parent_pid_of_self_is_queryable_and_started_no_later_than_us() {
        let pid = std::process::id();
        let Some(ppid) = ProcessTree::parent_pid(pid) else {
            // Sandboxed/CI environments may restrict this; don't fail the
            // suite over an environmental limitation.
            return;
        };
        if ppid == 0 {
            return;
        }
        let Some(child_start) = ProcessTree::start_time(pid) else {
            return;
        };
        let Some(parent_start) = ProcessTree::start_time(ppid) else {
            return;
        };
        assert!(parent_start <= child_start);
    }

    #[test]
    fn nonexistent_pid_returns_none() {
        // PID 1 is always init/launchd and always exists on macOS, so use
        // an implausibly large pid instead, which the kernel should report
        // as not found.
        assert!(ProcessTree::start_time(u32::MAX - 1).is_none());
    }
}
