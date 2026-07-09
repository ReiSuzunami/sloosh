# Contributing to sloosh

Thanks for taking a look. This is a small, security-sensitive tool, so the
bar for changes near the trust boundary (vault, lease, transport) is
intentionally higher than everywhere else — see below.

## Dev setup

You need a recent stable Rust toolchain (edition 2024, so `rustc >= 1.85`).

```
git clone https://github.com/ReiSuzunami/sloosh
cd sloosh
cargo build
```

No other setup is required — the daemon and CLI live in one binary
(`target/debug/sloosh`), and the non-live test suite doesn't touch the
network or your real `~/.sloosh`.

## Before you open a PR

These are the same checks CI runs; please run them locally first:

```
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

All three must pass cleanly. If `cargo fmt` reports a diff, run
`cargo fmt --all` and commit the result rather than hand-formatting.

## Running the live SSH tests

Most of the test suite (including `tests/daemon_status.rs`) runs without
any external dependency. The integration tests in `tests/ssh_session.rs`
(real SSH sessions: `run`/`peek`/`send`/`interrupt`/`open`/`ls`/`kill`) and
`tests/sftp_transfer.rs` (`put`/`get` over SFTP) need an actual reachable
host, so they're gated behind an environment variable and skipped
otherwise:

```
SLOOSH_TEST_SSH_HOST=myhost cargo test --test ssh_session -- --test-threads=1
SLOOSH_TEST_SSH_HOST=myhost cargo test --test sftp_transfer -- --test-threads=1
```

`myhost` can be an alias resolvable via `~/.ssh/config` or a literal
`user@host`/`host`. Single-threaded is required: each test redirects
`$SLOOSH_HOME` to its own temp directory so the run never touches your real
`~/.sloosh/vault`, and that isolation only holds with one test running at a
time. If `SLOOSH_TEST_SSH_HOST` is unset, these tests compile and pass
trivially by skipping — they never fail or hang waiting for network access
nobody granted, so it's safe to leave it unset in normal development.

## Security-sensitive areas get extra scrutiny

Changes touching any of the following will be held to a higher review bar,
and PRs there should explain their reasoning in more depth than usual:

- `src/daemon/vault.rs` — credential encryption at rest (argon2id +
  ChaCha20-Poly1305), zeroization, the vault's on-disk format.
- `src/daemon/lease.rs` — the authorization model: process-ancestry
  anchoring, the `SLOOSH_LEASE` escape hatch, approval/self-approval
  checks.
- `src/transport/` — the Unix domain socket transport and kernel
  peer-credential lookups that lease anchoring depends on.

If you're proposing a change in one of these areas, please open an issue or
draft PR early so the design can be discussed before you invest in a full
implementation. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the
English overview of how these pieces fit together, and
[`DESIGN.md`](DESIGN.md) for the full (Chinese) design document.

## PR flow

Nothing exotic: fork, branch, PR against `main`. No DCO or CLA — just make
sure the checks above pass and describe what you changed and why. Small,
focused PRs are much easier to review than large ones.
