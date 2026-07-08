//! Process tree introspection (DESIGN.md §4, §8).
//!
//! Lease anchoring walks the caller's process ancestry to find the top-level
//! Agent process, so subagents inherit the lease with zero configuration.
//! That walk needs a `parent_pid` + `start_time` lookup per platform (sysctl
//! on macOS, `/proc` on Linux); this module is the abstraction boundary so
//! no platform branch leaks into `daemon::lease`.
//!
//! Not wired into `daemon::lease` yet — lease management is a later
//! milestone — so the concrete implementations are silenced with
//! `allow(dead_code)` until then.

#![allow(dead_code)]

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
}
