# Contributing to sloosh

Sloosh is security-sensitive. Keep changes focused; explain trust-boundary
changes and test their failure paths.

## Setup

Requires current stable Rust plus MSRV 1.85. The
[README](README.en.md#build-from-source) covers checkout and release builds.

```sh
rustup toolchain install stable 1.85.0
cargo build --bins
```

The CLI and daemon are `target/debug/sloosh` and `target/debug/slooshd`.
Normal tests use temporary state and need neither network access nor real
`~/.sloosh` data.

## Required gate

Run before opening a pull request:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo +1.85.0 check --all-targets --all-features --locked
pnpm --dir gui install --frozen-lockfile
pnpm --dir gui check
pnpm --dir gui test:unit
scripts/check-versions.sh
scripts/check-lockfile-sync.sh
cargo check --manifest-path gui/src-tauri/Cargo.toml --locked
cargo test --manifest-path packaging/windows/native-approval/Cargo.toml --locked
cargo check --manifest-path packaging/windows/native-approval/Cargo.toml --locked
# Release binaries must embed the frontend rather than use devUrl:
cargo build --manifest-path gui/src-tauri/Cargo.toml --locked --release \
  --features custom-protocol
for target in aarch64-apple-darwin x86_64-apple-darwin x86_64-unknown-linux-musl x86_64-pc-windows-msvc; do
  cargo deny --all-features --target "$target" \
    check advisories bans licenses sources
done
for target in aarch64-apple-darwin x86_64-apple-darwin x86_64-pc-windows-msvc; do
  cargo deny --manifest-path gui/src-tauri/Cargo.toml --all-features \
    --target "$target" check advisories bans licenses sources
done
cargo deny --manifest-path packaging/windows/native-approval/Cargo.toml \
  --target x86_64-pc-windows-msvc check advisories bans licenses sources
git diff --check
```

Root CLI/daemon code retains MSRV 1.85. The isolated Tauri crate uses current
stable Rust and its own lockfile. Install
[cargo-deny](https://github.com/EmbarkStudios/cargo-deny) before running the
dependency checks. All commands must pass. Hosted CI repeats formatting, lint,
unit/integration tests on Linux and macOS, MSRV checking, dependency policy,
full-history secret scanning, and live SSH coverage against an isolated sshd.

## Live SSH tests

Live suites skip when required variables are unset. Run them single-threaded;
each suite redirects `SLOOSH_HOME` to temporary state.

```sh
SLOOSH_TEST_SSH_HOST=myhost cargo test --test ssh_session -- --test-threads=1
SLOOSH_TEST_SSH_HOST=myhost cargo test --features integration-test-hooks \
  --test sftp_transfer -- --test-threads=1
SLOOSH_TEST_SSH_HOST=myhost cargo test --features integration-test-hooks \
  --test forward -- --test-threads=1
SLOOSH_TEST_SSH_HOST=user@host SLOOSH_TEST_SSH_PASSWORD=... \
  cargo test --test proxy_jump -- --test-threads=1
```

`myhost` may be an SSH config alias, `user@host`, or `host`. The first three
suites run in hosted CI. ProxyJump requires password authentication and an
isolated test host, so it remains manual. Never claim a skipped suite exercised
its network path.

`integration-test-hooks` is test-only; never expose it through CLI or protocol.

## Contract changes

Read and update the owner before changing a trust boundary:

- [`SECURITY.md`](SECURITY.md): threat model, capabilities, limits, permissions;
- [`architecture.md`](docs/internals/architecture.md): components and runtime;
- [`protocol.md`](docs/internals/protocol.md): wire shapes, framing, sequencing.

Incompatible wire changes must bump `WIRE_PROTOCOL_VERSION`, update client and
daemon, and add mismatch/upgrade tests. User-visible changes also update
README, `--help`, translations, and agent skill where relevant.

PRs target `main`; no DCO or CLA is required. Describe what changed and why.
