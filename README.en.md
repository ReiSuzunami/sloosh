# sloosh

[简体中文](./README.md) | English

[![CI](https://github.com/ReiSuzunami/sloosh/actions/workflows/ci.yml/badge.svg)](https://github.com/ReiSuzunami/sloosh/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Persistent SSH sessions for coding agents. System SSH-agent credentials can
authorize automatically; passwords, key files, and custom agents still need
out-of-band human approval. Agents never receive secrets.

## Install

Once prebuilt versions are available, download one from the
[latest GitHub Release](https://github.com/ReiSuzunami/sloosh/releases/latest):

- macOS desktop control plane: `Sloosh-<version>-macos-universal.dmg`
- macOS command-line package: `sloosh-macos-universal.tar.gz`
- Linux x86_64: `sloosh-linux-x86_64-musl.tar.gz`

The DMG installs only the desktop control plane and its private daemon; it does
not put the `sloosh` CLI in `PATH`. Homebrew, crates.io, and the command-line
archives provide `sloosh` with its companion `slooshd`, but do not include or
build the desktop app. The app and DMG are distributed only through GitHub
Releases.

See the [installation guide](./docs/getting-started/installation.md) for
checksums, platform requirements, and upgrades.

## Let your agent install it

**Paste this entire prompt to your agent. / 将此 Prompt 粘贴给你的 Agent。**

```text
You are my sloosh installation guide.

1. Detect the OS and architecture, then run `command -v sloosh && sloosh --version`.
   Use only `https://github.com/ReiSuzunami/sloosh`. If sloosh is missing or old,
   choose Homebrew or the matching command-line archive and verify
   `SHA256SUMS`, or explain the Rust 1.85+ source build when no release exists.
   The macOS DMG is an optional desktop control plane and does not provide the
   CLI. Ask before installing anything. Never use `curl | sh`, silently invoke
   a package manager, bypass platform protections, request/display passwords,
   SSH keys, vault secrets, or lease tokens, or run `slooshd` directly.
2. Once the CLI works, explain `sloosh init` and ask me to run it in my own
   interactive terminal. Do not run it, fake a TTY, or enter/read any secret.
   If I also install the desktop app, guide me to complete native unlock setup
   myself in its Setup/Security screens.
3. After I confirm completion, run only `sloosh skill status --agent auto` and
   `sloosh status`, then report the results. A complete host scope that uses
   only the default system SSH agent with no key-file fallback gets a bounded
   lease automatically; other host access still needs out-of-band human
   approval. I must always confirm unknown or changed host keys.
```

Without an agent, follow the [manual](./docs/manual.md) for initialization and
the first connection.

## Build from source

Requires Rust 1.85+ and a C/C++ build toolchain:

```sh
git clone https://github.com/ReiSuzunami/sloosh.git
cd sloosh
cargo build --release --bins --locked
```

The client and daemon are written to `target/release/sloosh` and
`target/release/slooshd`.

## Documentation

- [Manual](./docs/manual.md)
- [Installation and upgrades](./docs/getting-started/installation.md)
- [Security model](./SECURITY.md)
- [Architecture](./docs/internals/architecture.md) · [Protocol](./docs/internals/protocol.md)
- [Contributing](./CONTRIBUTING.md) · [Support](./SUPPORT.md)
- [Complete documentation index](https://github.com/ReiSuzunami/sloosh/blob/main/docs/README.md)

## License

[MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE), at your option.
