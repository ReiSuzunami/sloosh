//! sloosh: SSH-in-the-loop for coding agents (docs/internals/architecture.md).
//!
//! Split into a library + thin binary so integration tests can drive the
//! daemon and transport layers directly.

pub mod cli;
pub use cli::client;
pub mod daemon;
pub mod local_approval;
pub mod native_approval;
pub mod procs;
pub mod proto;
pub mod transport;
pub mod vault_settings;
