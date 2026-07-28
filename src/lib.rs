//! sloosh: SSH-in-the-loop for coding agents (docs/internals/architecture.md).
//!
//! Split into a library plus thin `sloosh` and `slooshd` binaries so clients
//! and integration tests share the daemon and transport implementation.

pub mod cli;
pub use cli::client;
pub mod daemon;
pub(crate) mod diagnostics;
pub mod local_approval;
pub mod native_approval;
pub mod procs;
pub mod proto;
pub mod transport;
pub mod vault_settings;
