# Contributing to sloosh

Thanks for taking a look. This is a small, security-sensitive tool, so changes
near a trust boundary need explicit reasoning and focused tests.

## Dev setup

The minimum supported Rust version (MSRV) is 1.85. Normal development uses a
current stable toolchain; CI separately verifies that the code still checks
with Rust 1.85.

```
git clone https://github.com/ReiSuzunami/sloosh
cd sloosh
rustup toolchain install stable 1.85.0
cargo build
```

No other setup is required — the daemon and CLI live in one binary
(`target/debug/sloosh`), and the non-live test suite doesn't touch the
network or your real `~/.sloosh`.

## Before you open a PR

Run the full local gate before opening a PR:

```
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo +1.85.0 check --all-targets --all-features --locked
git diff --check
```

All five must pass cleanly. If `cargo fmt` reports a diff, run
`cargo fmt --all` and commit the result rather than hand-formatting.

CI maps these checks as follows:

| Job | Platform/toolchain | Coverage |
|---|---|---|
| `lint` | Ubuntu, stable | `cargo fmt --all --check` and strict clippy |
| `test` | Ubuntu + macOS, stable | Unit tests and non-live integration tests |
| `msrv` | Ubuntu, Rust 1.85 | `cargo check --all-targets --all-features --locked` |
| `live-ssh` | Ubuntu, stable | Live session, SFTP, and local/remote-forward tests against a local sshd |

## Running the live SSH tests

Most tests, including `tests/daemon_status.rs`, run without a network or the
real `~/.sloosh`. Live suites skip when their environment variables are not
set:

| Test | Exercises | Required environment | Hosted CI |
|---|---|---|---|
| `ssh_session` | Persistent PTY operations and session lifecycle | `SLOOSH_TEST_SSH_HOST` | Yes |
| `sftp_transfer` | Streaming `put`/`get`, >32 MiB no-total-cap, in-flight lease expiry, and PTY-reaper survival | `SLOOSH_TEST_SSH_HOST` | Yes |
| `forward` | Local and remote forwarding plus lease teardown | `SLOOSH_TEST_SSH_HOST` | Yes |
| `proxy_jump` | Vault-backed jump, tunneled handshake, per-hop lease | `SLOOSH_TEST_SSH_HOST`, `SLOOSH_TEST_SSH_PASSWORD` | Manual |

```
SLOOSH_TEST_SSH_HOST=myhost cargo test --test ssh_session -- --test-threads=1
SLOOSH_TEST_SSH_HOST=myhost cargo test --features integration-test-hooks \
  --test sftp_transfer -- --test-threads=1
SLOOSH_TEST_SSH_HOST=myhost cargo test --features integration-test-hooks \
  --test forward -- --test-threads=1
SLOOSH_TEST_SSH_HOST=user@host SLOOSH_TEST_SSH_PASSWORD=... \
  cargo test --test proxy_jump -- --test-threads=1
```

`myhost` can be an alias resolvable via `~/.ssh/config` or a literal
`user@host`/`host`. Single-threaded is required: each test redirects
`$SLOOSH_HOME` to its own temp directory so the run never touches your real
`~/.sloosh/vault`, and that isolation only holds with one test running at a
time. If `SLOOSH_TEST_SSH_HOST` is unset, these tests compile and pass
trivially by skipping — they never fail or hang waiting for network access
nobody granted, so it's safe to leave it unset in normal development.

The live ProxyJump suite needs password authentication and is intentionally
not enabled against the hosted runner's system sshd. Run it manually against
an isolated test host.

## Security-sensitive areas get extra scrutiny

Changes touching any of the following will be held to a higher review bar,
and PRs there should explain their reasoning in more depth than usual:

- `src/proto.rs`, `src/transport/`, and `src/cli/client.rs` — wire protocol 1,
  control-message limits, raw transfer framing, peer identity, daemon version
  checks, and private socket/log paths.
- `src/daemon/lease.rs` and `src/daemon/forward.rs` — process-ancestry
  anchoring, the `SLOOSH_LEASE` escape hatch, approval checks, stable grants,
  and teardown of live network access.
- `src/daemon/vault.rs`, `src/daemon/ssh.rs`, and `src/daemon/audit.rs` —
  encrypted credentials, serialized/atomic mutation, ProxyJump, host-key
  verification, zeroization, and secret-safe logging.
- `src/daemon/session.rs` and the transfer code in `src/cli/mod.rs` — PTY
  framing, spool retention, local filesystem authority, SFTP streaming, and
  atomic local downloads.

Keep these contracts intact unless the change explicitly revises them:

- Protocol 1 control messages are bounded NDJSON. SFTP data uses raw frames
  capped at 1 MiB each, with no total transfer-size cap.
- Connection setup is bidirectional: the CLI validates `Status`, then sends
  `Hello` and waits for `ProtocolReady`. The daemon rejects ordinary requests
  before a successful handshake, without performing their side effects.
- The CLI is the only process that opens a `put`/`get` local path. The daemon
  treats that path as an audit/display label and owns only the remote SFTP
  handle.
- A transfer is lease-authorized once before `TransferReady`, with no per-frame
  re-check. A finite transfer already in flight may finish after the two-hour
  idle or eight-hour absolute lease expiry; expiry blocks new operations, not
  bytes in that stream.
- SFTP replaces `russh-sftp`'s 10-second request default with the pinned
  Tokio far-future deadline (roughly 30 years); do not restore the short
  default, which breaks slow NAS operations.
- `get` requests mode `0666` for its temporary file, lets the caller's umask
  determine the effective mode, and does not clobber by default. `put`
  truncates the remote destination and is not atomic remotely.
- Local forwards bind only loopback addresses. Remote (`-R`) forwarding is
  supported under the host lease and may expose a listener according to the
  SSH server's `GatewayPorts` policy.
- Command-output spool persistence is bounded at 64 MiB per run, 64 MiB per
  session directory, and 1 GiB globally by actual persisted bytes. Active runs
  do not reserve their unused allowance, and cleanup failure must not fail a
  command. Spool is separate from SFTP and is not an unlimited/complete
  command-output archive. Synchronous append/eviction latency on a slow spool
  filesystem remains a known limitation; do not add per-run full-tree scans.

Any incompatible request, response, framing, or sequencing change must bump
`WIRE_PROTOCOL_VERSION`, update both client and daemon handling, and add a
mismatch/upgrade test. User-visible behavior changes must update README,
command help, and the agent skill where relevant.

If you're proposing a change in one of these areas, please open an issue or
draft PR early so the design can be discussed before you invest in a full
implementation. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the
English overview of how these pieces fit together, and
[`DESIGN.md`](DESIGN.md) for the full (Chinese) design document.

## PR flow

Nothing exotic: fork, branch, PR against `main`. No DCO or CLA — just make
sure the checks above pass and describe what you changed and why. Small,
focused PRs are much easier to review than large ones.
