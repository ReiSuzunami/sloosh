//! PTY session management: sentinel-based output splitting, ring buffer,
//! cursor-based `peek`, spool to disk (DESIGN.md §3, §5). Implemented in a
//! later milestone.

use crate::proto::SessionSummary;

/// Summaries of all live sessions, for `status`/`ls`. Empty until session
/// management lands.
pub fn list_summaries() -> Vec<SessionSummary> {
    Vec::new()
}
