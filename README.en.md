# sloosh

[简体中文](./README.md) | English

[![CI](https://github.com/ReiSuzunami/sloosh/actions/workflows/ci.yml/badge.svg)](https://github.com/ReiSuzunami/sloosh/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Persistent SSH sessions with out-of-band human approval for coding agents;
agents never need passwords or private keys.

## Install

Once prebuilt versions are available, download one from the
[latest GitHub Release](https://github.com/ReiSuzunami/sloosh/releases/latest):

- macOS desktop app and CLI: `Sloosh-<version>-macos-universal.dmg`
- macOS standalone CLI: `sloosh-macos-universal.tar.gz`
- Linux x86_64: `sloosh-linux-x86_64-musl.tar.gz`

See the [installation guide](./docs/getting-started/installation.md) for
checksums, platform requirements, and upgrades.

## Let your agent install it

**Paste this entire prompt to your agent. / 将此 Prompt 粘贴给你的 Agent。**

```text
You are my sloosh installation guide.

1. Detect the OS and architecture, then run `command -v sloosh && sloosh --version`.
   Use only `https://github.com/ReiSuzunami/sloosh`. If sloosh is missing or old,
   check the latest Release: choose the matching DMG/archive and verify
   `SHA256SUMS`, or explain the Rust 1.85+ source build when no release exists.
   Ask before installing anything. Never use `curl | sh`, silently invoke a
   package manager, bypass platform protections, or request/display passwords,
   SSH keys, vault secrets, or lease tokens.
2. Once the binary works, explain `sloosh init` and ask me to run it in my own
   interactive terminal. Do not run it, fake a TTY, or enter/read any secret.
3. After I confirm completion, run only `sloosh skill status --agent auto` and
   `sloosh status`, then report the results. Host access still requires
   out-of-band human approval.
```

Without an agent, follow the [manual](./docs/manual.md) for initialization and
the first connection.

## Build from source

Requires Rust 1.85+ and a C/C++ build toolchain:

```sh
git clone https://github.com/ReiSuzunami/sloosh.git
cd sloosh
cargo build --release --locked
```

The binary is written to `target/release/sloosh`.

## Documentation

- [Manual](./docs/manual.md)
- [Installation and upgrades](./docs/getting-started/installation.md)
- [Security model](./SECURITY.md)
- [Architecture](./docs/internals/architecture.md) · [Protocol](./docs/internals/protocol.md)
- [Contributing](./CONTRIBUTING.md) · [Support](./SUPPORT.md)
- [Complete documentation index](https://github.com/ReiSuzunami/sloosh/blob/main/docs/README.md)

## License

[MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE), at your option.
