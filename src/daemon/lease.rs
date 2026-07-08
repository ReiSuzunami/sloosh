//! Authorization leases: process-ancestry anchoring, `SLOOSH_LEASE` escape
//! hatch, idle timeout (DESIGN.md §4). Implemented in a later milestone.

use crate::proto::LeaseSummary;

/// Summaries of all active leases, for `status`. Empty until lease
/// management lands.
pub fn list_summaries() -> Vec<LeaseSummary> {
    Vec::new()
}
