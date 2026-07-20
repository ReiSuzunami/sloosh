# Agent Guide

Canonical repository guidance for coding agents. `CLAUDE.md` must remain a
relative symlink to this file.

## Behavior

- Always use `caveman`; use `caveman-commit` for commits and `caveman-review`
  for reviews and pull requests.
- Inspect implementation and tests before proposing changes.
- Keep changes focused and preserve unrelated work in a dirty tree.

## Project contract

`sloosh` is a security-sensitive Rust 2024 CLI and daemon for persistent SSH
sessions, human-approved host leases, SFTP, and forwarding on macOS and Linux.
MSRV is Rust 1.85; runtime is Tokio with `russh` and `russh-sftp`.

Read each owner relevant to the change:

| Owner | Contract |
|---|---|
| [`README.md`](README.md) and `--help` | User-visible behavior |
| [`SECURITY.md`](SECURITY.md) | Threat model, guarantees, limits, permissions |
| [`architecture.md`](docs/internals/architecture.md) | Components, data ownership, runtime |
| [`protocol.md`](docs/internals/protocol.md) | Wire schema, framing, sequencing |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Development, CI, and live tests |
| [`releasing.md`](docs/maintainers/releasing.md) | Releases |
| [`skills/sloosh/SKILL.md`](skills/sloosh/SKILL.md) | Agent operations |

When code, tests, and docs disagree, verify runtime behavior, fix code or tests,
then update every affected owner and translation in the same change.

## Guardrails

- Daemon is authority. Host access needs a human-approved lease bound to PID
  plus start time, or a valid `SLOOSH_LEASE` token. Approval stays out of band
  and cannot come from requesting process tree.
- Wire protocol remains version 3 until a concrete incompatible schema,
  framing, default, or sequencing change. Such changes require a version bump
  and mismatch/upgrade tests. CLI verifies daemon eUID and executable path,
  then performs `Status -> Hello -> ProtocolReady` before ordinary requests.
- Never pass or log vault passwords, SSH passwords, private keys, lease tokens,
  interactive `send` contents, or decrypted vault data. Use redacted and
  zeroizing secret types.
- CLI alone opens SFTP local paths; daemon treats `local_path` as a label. `get`
  uses a same-directory `create_new` temp file and atomic commit. `put`
  truncates remote destination and is not remotely atomic.
- SFTP is authorized before `TransferReady`; an in-flight transfer may finish
  after lease expiry, while new operations fail. Raw frames and control
  messages stay bounded as specified by protocol and security owners.
- Local forwarding binds loopback only. Remote forwarding is deliberate
  exposure governed by sshd `GatewayPorts`. Forwards retain stable
  `LeaseGrant`; remote routes remain monotonic `Pending -> Active -> Closed`.
- Vault/state paths retain documented ownership, mode, symlink, ACL,
  `O_NOFOLLOW`, serialization, and atomic-write controls.
- PTY ring, reply, spool, session, and root budgets remain bounded exactly as
  documented in `SECURITY.md`. Never make spool failure fail a command, erase
  active files, or reintroduce full-tree scans per run. Current synchronous
  spool I/O is not latency-isolated.
- Host-key mismatch fails closed. Unknown targets follow real ProxyJump route
  and require human fingerprint confirmation. Vault-backed jumps need lease
  coverage.
- `integration-test-hooks` stays test-only and must never appear in CLI or wire
  protocol.

## Workflow

1. Identify changed contract and read its owner, owning module, and focused tests.
2. Make smallest change preserving authority and resource bounds.
3. Add success, failure, and mismatch tests proportional to risk.
4. Update affected docs, help, translations, and skill.
5. Run focused tests, then full gate from `CONTRIBUTING.md`.
6. Review diff for secret exposure, authority movement, races, unbounded
   allocation, and stale docs.

Do not add abstraction unless it removes real complexity or matches an existing
pattern. Do not broaden forwarding, filesystem, or credential authority.

## Rust and tests

- Keep rustfmt and strict Clippy clean; preserve Rust 1.85 compatibility.
- Prefer typed errors and self-teaching messages over string parsing.
- Bound attacker-controlled lengths before allocation.
- Keep `unsafe` minimal with a concrete `SAFETY` comment.
- Unit-test pure state machines beside modules; put cross-module daemon behavior
  in `tests/`.
- Normal tests never touch real `~/.sloosh` or require network. Live tests need
  explicit hosts, isolated `SLOOSH_HOME`, and one test thread. If variables are
  unset and tests skip, report that honestly.

Do not commit `target/`, credentials, `.env*`, `.gh-config/`, real vaults,
known-host data, daemon/audit logs, or spool output.
