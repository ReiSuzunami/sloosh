# Agent Guide

This file is the canonical repository guidance for coding agents. `CLAUDE.md`
must remain a relative symlink to this file so both entry points stay aligned.

## Agent Behavior

- Always use the `caveman` skill for concise, high-signal communication.
- Use `caveman-commit` when creating commits.
- Use `caveman-review` for code-review and pull-request messages.
- Inspect the real implementation and tests before proposing changes.
- Keep changes focused. Preserve unrelated user work in a dirty worktree.

## Project

`sloosh` is a security-sensitive Rust CLI and background daemon for persistent
SSH sessions, human-approved host leases, SFTP, and local/remote forwarding.
CLI and daemon are subcommands of one binary. Supported platforms are macOS
and Linux.

Toolchain:

- Rust edition 2024
- MSRV 1.85
- Tokio async runtime
- `russh` and `russh-sftp` for SSH/SFTP

## Read First

Read only the documents relevant to the task, but treat these as the project
contract:

- `README.md`: user-visible behavior and command overview.
- `DESIGN.md`: authoritative Chinese design and implementation status.
- `docs/ARCHITECTURE.md`: component boundaries and data ownership.
- `SECURITY.md`: threat model, guarantees, and known limits.
- `docs/PROTOCOL.md`: exact CLI-daemon protocol and framing.
- `CONTRIBUTING.md`: development, CI, and live-test commands.

When code, tests, and docs disagree, verify runtime behavior, fix the code or
tests as needed, then update every affected document in the same change.

## Code Map

- `src/cli/args.rs`: Clap command and option definitions.
- `src/cli/client.rs`: daemon connection, spawn, identity, and protocol gate.
- `src/cli/mod.rs`: command dispatch, approval UI, and local SFTP files.
- `src/daemon/mod.rs`: request authorization and daemon dispatch.
- `src/daemon/session.rs`: PTY sessions, framing, spool, and remote SFTP.
- `src/daemon/lease.rs`: pending requests, ancestry leases, and stable grants.
- `src/daemon/forward.rs`: local/remote forwarding and lease teardown.
- `src/daemon/ssh.rs`: SSH config, auth, ProxyJump, and host-key checks.
- `src/daemon/vault.rs`: encrypted vault, atomic mutation, and cache lifecycle.
- `src/daemon/audit.rs`: private NDJSON audit log.
- `src/proto.rs`: versioned request/response schema.
- `src/transport/`: bounded UDS framing and peer credentials.
- `src/procs/`: Linux/macOS process ancestry inspection.
- `tests/`: daemon and live SSH integration suites.

## Non-Negotiable Contracts

### IPC and protocol

- Current wire protocol is version 1. The project is still pre-release; do not
  bump it without a concrete incompatible wire change.
- CLI verifies daemon eUID and canonical executable path.
- CLI performs `Status -> Hello -> ProtocolReady` before ordinary requests.
- Daemon rejects unnegotiated ordinary requests before side effects.
- Control NDJSON is capped at 1 MiB including newline.
- SFTP raw frames are capped at 1 MiB each. Frame count and total file size are
  not capped.
- Any incompatible schema, tag, default, framing, or sequencing change must
  bump `WIRE_PROTOCOL_VERSION` and add mismatch/upgrade tests.

### Authorization

- Daemon is the authority. CLI checks alone are never sufficient.
- Host access requires a human-approved lease bound to PID plus start time, or
  a valid `SLOOSH_LEASE` token.
- Approval must remain out of band and reject self-approval from the requesting
  process tree.
- Vault-backed ProxyJump hops require explicit lease coverage.
- Forwards retain stable `LeaseGrant` values, not short-lived CLI PIDs.
- SFTP is authorized once before `TransferReady`. An in-flight transfer may
  complete after lease expiry; new operations must fail.

### Secrets and files

- Never pass or log vault passwords, SSH passwords, private keys, lease tokens,
  interactive `send` contents, or decrypted vault data.
- Use redacted/zeroizing types for secret material.
- CLI alone opens SFTP local paths. Daemon treats `local_path` as a label.
- `get` uses a same-directory `create_new` temp file with requested mode
  `0666`, so the caller's umask determines the final mode, then commits
  atomically.
- `put` truncates the remote destination and is not remotely atomic.
- Vault writes stay serialized, mode `0600`, and atomic via unique temp rename.
- Private directories stay `0700`; sockets/logs/spool/vault stay `0600` where
  applicable. Preserve symlink, ownership, ACL, and `O_NOFOLLOW` checks.

### Network and resources

- Local forwarding binds loopback only.
- Remote `-R` forwarding is supported under the host lease. Treat its remote
  listener as deliberate network exposure; the SSH server's `GatewayPorts`
  policy controls whether a non-loopback bind is externally reachable.
- A remote route is monotonic `Pending -> Active -> Closed`. Only `Active`
  routes may dial the local target; stop/expiry closes the route before any
  remote cancellation await, and cancellation must remain time-bounded.
- Host-key mismatches fail closed. Unknown target probing must follow the real
  ProxyJump route and require human fingerprint confirmation.
- PTY output limits are 256 KiB ring, about 30,000 reply characters, 64 MiB per
  run spool, 64 MiB per session retention, and 1 GiB global spool budget.
- The spool root budget is charged by bytes actually persisted. Active runs do
  not reserve unused capacity; cleanup failures may stop further persistence
  at the cap but must never fail the command or erase active files.
- Spool files are collision-safe `create_new` files. Session recreation or a
  daemon restart must never truncate a retained file with a reused run number.
- An incomplete initial spool index fails closed for persistence and retries
  later; command processing and the memory ring remain available.
- Do not reintroduce full-tree scans at each run boundary. Current synchronous
  append/eviction calls can still delay PTY consumption on a slow spool
  filesystem; move them off the reader path before claiming latency isolation.
- Spool limits apply only to command output, never to SFTP bytes.
- `russh-sftp`'s short request timeout must remain replaced by the pinned
  Tokio far-future deadline for slow NAS operations.

## Change Workflow

1. Reproduce or identify the exact contract being changed.
2. Read the owning module and focused tests before editing.
3. Make the smallest change that preserves trust boundaries.
4. Add tests proportional to risk, including failure and mismatch paths.
5. Update user, architecture, security, protocol, and skill docs when their
   behavior changes.
6. Run focused tests first, then the full required gates.
7. Review the final diff for secret exposure, authority movement, races,
   unbounded allocation, and stale documentation.

Do not add an abstraction unless it removes real complexity or matches an
existing project pattern. Do not silently broaden forwarding, filesystem, or
credential authority.

## Required Checks

Run from repository root:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo +1.85.0 check --all-targets --all-features --locked
git diff --check
```

Normal tests must not touch the real `~/.sloosh` or require network access.

Live tests require an explicit test host and must run single-threaded:

```sh
SLOOSH_TEST_SSH_HOST=myhost cargo test --test ssh_session -- --test-threads=1
SLOOSH_TEST_SSH_HOST=myhost cargo test --features integration-test-hooks \
  --test sftp_transfer -- --test-threads=1
SLOOSH_TEST_SSH_HOST=myhost cargo test --features integration-test-hooks \
  --test forward -- --test-threads=1
```

`tests/proxy_jump.rs` also requires `SLOOSH_TEST_SSH_PASSWORD` and should use
an isolated test host. If live-test variables are unset, tests skip; report
that honestly rather than claiming the network path ran.

`integration-test-hooks` is test-only. Never expose its behavior through CLI
or wire protocol.

## Rust and Test Style

- Follow `rustfmt`; keep strict Clippy clean on all targets and features.
- Preserve Rust 1.85 compatibility.
- Prefer typed errors and self-teaching user messages over string parsing.
- Bound allocations before reading attacker-controlled lengths.
- Keep `unsafe` blocks minimal and include a concrete `SAFETY` comment.
- Unit-test pure state machines beside their modules.
- Put cross-module daemon behavior in `tests/`.
- Keep live SSH tests gated, isolated under temporary `SLOOSH_HOME`, and
  single-threaded.

## Documentation Map

- User-visible command or behavior: `README.md` and relevant `--help` text.
- Agent workflow: `skills/sloosh/SKILL.md`.
- Architecture/ownership: `docs/ARCHITECTURE.md`.
- Threat model or capability boundary: `SECURITY.md`.
- Wire behavior: `docs/PROTOCOL.md` and `WIRE_PROTOCOL_VERSION` when needed.
- Design/status: `DESIGN.md`.
- Development or test workflow: `CONTRIBUTING.md` and CI.

Do not commit `target/`, credentials, local `.env*`, `.gh-config/`, real vaults,
known-host data, daemon logs, audit logs, or spool output.
