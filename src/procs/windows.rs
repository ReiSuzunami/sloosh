use super::{AncestorInfo, ProcessInfo, ancestry_chain};
use std::ffi::OsString;
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt as _;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};

pub struct ProcessTree;

impl ProcessTree {
    pub fn ancestry(pid: u32) -> Vec<AncestorInfo> {
        ancestry_chain::<Self>(pid)
    }
}

impl ProcessInfo for ProcessTree {
    fn parent_pid(pid: u32) -> Option<u32> {
        snapshot_entry(pid).map(|entry| entry.th32ParentProcessID)
    }

    fn start_time(pid: u32) -> Option<SystemTime> {
        let process = open_process(pid)?;
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: all pointers refer to initialized writable FILETIME values.
        let result =
            unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) };
        // SAFETY: `process` is a live owned handle from OpenProcess.
        let _ = unsafe { CloseHandle(process) };
        result.ok()?;
        filetime_to_system_time(created)
    }

    fn exe_basename(pid: u32) -> Option<String> {
        snapshot_entry(pid).and_then(|entry| {
            let end = entry
                .szExeFile
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(entry.szExeFile.len());
            OsString::from_wide(&entry.szExeFile[..end])
                .into_string()
                .ok()
        })
    }

    fn exe_path_basename(pid: u32) -> Option<String> {
        process_path(pid)?
            .file_name()?
            .to_string_lossy()
            .into_owned()
            .into()
    }

    fn argv0_basename(_pid: u32) -> Option<String> {
        // Reading another process's PEB command line is deliberately avoided;
        // Windows supplies two independent kernel-backed executable signals.
        None
    }
}

fn snapshot_entry(pid: u32) -> Option<PROCESSENTRY32W> {
    // SAFETY: snapshot is closed before returning; PROCESSENTRY32W has the
    // documented dwSize initialized before enumeration.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found = None;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == pid {
                    found = Some(entry);
                    break;
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        found
    }
}

fn open_process(pid: u32) -> Option<HANDLE> {
    // SAFETY: the returned handle is owned by the caller.
    unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok() }
}

fn process_path(pid: u32) -> Option<PathBuf> {
    let process = open_process(pid)?;
    let mut buffer = vec![0_u16; 32_768];
    let mut length = buffer.len() as u32;
    // SAFETY: buffer and length describe writable storage; the handle has
    // PROCESS_QUERY_LIMITED_INFORMATION access.
    let result = unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    };
    // SAFETY: `process` is owned by this function.
    let _ = unsafe { CloseHandle(process) };
    result.ok()?;
    buffer.truncate(length as usize);
    Some(PathBuf::from(OsString::from_wide(&buffer)))
}

fn filetime_to_system_time(filetime: FILETIME) -> Option<SystemTime> {
    const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
    let ticks = (u64::from(filetime.dwHighDateTime) << 32) | u64::from(filetime.dwLowDateTime);
    let unix_ticks = ticks.checked_sub(WINDOWS_TO_UNIX_EPOCH_100NS)?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_nanos(unix_ticks.saturating_mul(100)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_has_stable_windows_identity() {
        let pid = std::process::id();
        let chain = ProcessTree::ancestry(pid);
        assert!(!chain.is_empty());
        assert_eq!(chain[0].pid, pid);
        assert!(chain[0].start_time <= SystemTime::now());
        assert!(chain[0].exe_path_basename.is_some());
    }
}
