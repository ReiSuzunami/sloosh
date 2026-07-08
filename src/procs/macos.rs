//! macOS process tree introspection via `sysctl(KERN_PROC_PID)`.
//! Real implementation lands with `daemon::lease` in a later milestone.

use super::ProcessInfo;
use std::time::SystemTime;

pub struct ProcessTree;

impl ProcessInfo for ProcessTree {
    fn parent_pid(_pid: u32) -> Option<u32> {
        None
    }

    fn start_time(_pid: u32) -> Option<SystemTime> {
        None
    }
}
