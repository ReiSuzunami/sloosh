//! sloosh: SSH-in-the-loop for coding agents (DESIGN.md).
//!
//! Split into a library + thin binary so integration tests can drive the
//! daemon and transport layers directly.

pub mod cli;
pub mod daemon;
pub mod procs;
pub mod proto;
pub mod transport;
