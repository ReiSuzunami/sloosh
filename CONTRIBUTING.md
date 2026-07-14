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

Do not copy their detailed contracts into a PR description. Link the owner
document and explain the exact boundary being changed:

- [`SECURITY.md`](SECURITY.md) owns the threat model and capability boundary.
- [`docs/internals/architecture.md`](docs/internals/architecture.md) owns
  component boundaries and runtime behavior.
- [`docs/internals/protocol.md`](docs/internals/protocol.md) owns wire shapes,
  framing, and sequencing.

Any incompatible wire change must bump `WIRE_PROTOCOL_VERSION`, update both
client and daemon handling, and add mismatch/upgrade tests. User-visible
behavior must update README, command help, and the agent skill where relevant.
Open an issue or draft PR early for changes that move credential, filesystem,
forwarding, or authorization authority.

## PR flow

Nothing exotic: fork, branch, PR against `main`. No DCO or CLA — just make
sure the checks above pass and describe what you changed and why. Small,
focused PRs are much easier to review than large ones.
