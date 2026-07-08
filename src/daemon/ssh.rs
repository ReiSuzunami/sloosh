//! SSH connection establishment via `russh`, `~/.ssh/config` subset parsing
//! (`Host`, `HostName`, `Port`, `User`, `IdentityFile`, `ProxyJump`), and
//! known_hosts handling (DESIGN.md §2, §3). Implemented in a later
//! milestone — no `russh` dependency yet.
