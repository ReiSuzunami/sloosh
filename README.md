# sloosh

English | [简体中文](./README.zh-CN.md)

[![CI](https://github.com/ReiSuzunami/sloosh/actions/workflows/ci.yml/badge.svg)](https://github.com/ReiSuzunami/sloosh/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Persistent SSH sessions with human-approved credential access for coding agents.

## Install

Download the release file for your platform from the
[latest GitHub Release](https://github.com/ReiSuzunami/sloosh/releases/latest):

- macOS DMG (Apple silicon or Intel): `Sloosh-<version>-macos-universal.dmg`
- macOS CLI archive (Apple silicon or Intel): `sloosh-macos-universal.tar.gz`
- Linux x86_64: `sloosh-linux-x86_64-musl.tar.gz`

For the DMG, double-click `Install Sloosh`. It copies `Sloosh.app` to
Applications, creates `~/.local/bin/sloosh` when that path is available,
ejects the disk image, and offers to move the DMG to Trash. An unrelated item
already at the CLI path is preserved. Open Sloosh to install the embedded
Agent Skill, initialize the vault, and enable Touch ID or an optional 6-digit
approval PIN. Before enrollment, the app explains what is stored in the macOS
login Keychain and what to expect from its native access prompt. The complete
CLI remains installed alongside the app.
During an update, the installer explicitly asks before quitting a running
Sloosh app; it force quits only after a 5-second graceful-exit timeout.

For an archive, extract it, then install the binary somewhere on `PATH`:

```sh
install -d "$HOME/.local/bin"
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
sloosh --version
```

See the [installation guide](./docs/getting-started/installation.md) for checksum
verification and platform notes.

## First-time setup

The recommended agent-first flow is to install the Agent Skill, then let it
check for the `sloosh` binary and guide the human through installation:

```sh
# Codex
codex plugin marketplace add ReiSuzunami/nerv
codex plugin add sloosh@nerv

# Any Agent Skills-compatible agent
npx skills add ReiSuzunami/sloosh
```

Claude Code users can add `ReiSuzunami/nerv` as a plugin marketplace and
install `sloosh@nerv`. These package commands distribute the Skill only; the
Skill asks before proposing any binary installation.

If the binary is installed first, run this in a human terminal:

```sh
sloosh init
```

`sloosh init` installs the Skill embedded in the binary and initializes the
credential vault. The macOS DMG build also enrolls Touch ID for later lease
requests; before enrollment, the CLI explains the login Keychain item, the
possible `Sloosh Approval` prompt, and the difference between `Allow` and
`Always Allow`. Rerunning `sloosh init` enables it for an existing vault. It
auto-detects Codex and Claude Code; use
`sloosh skill status` to inspect the result. The binary never invokes `npx` or
an agent marketplace itself.

After enrollment, `sloosh request` shows a native exact host-list confirmation,
then completes approval with Touch ID or the optional approval PIN, without
requiring another terminal. The PIN has persistent backoff and disables after
15 failed attempts; it is independent from the Master Password attempt budget.
Cancellation, missing enrollment, and source/archive builds fall back to `sloosh approve`.
The first request involving an unknown SSH host key also uses terminal approval
so the human can verify its fingerprint.

Linux needs no Keychain, Touch ID, or native-helper permission. At the end of
`sloosh init`, the CLI explains that later pending leases are approved from
another terminal with the printed `sloosh approve <ID>` command.

## Manage hosts

The desktop app includes a locked Hosts view for vault-backed connection
profiles. Authentication is explicit: SSH agent, an encrypted vault password,
or an unencrypted private-key path. Routes are direct, through another managed
host, or an advanced OpenSSH ProxyJump expression. Unlock once with Touch ID,
the 6-digit Sloosh PIN, or Master Password; the Rust desktop process keeps a
zeroizing session until the shared 1/5/15/30-minute idle timeout. It locks on
macOS sleep, screen lock or user switch, manual lock, app exit, or the fixed
8-hour ceiling. Master Password and PIN entry stay in the native helper. The
desktop SSH Password field is transient, crosses the
local Tauri command boundary as a redacted secret, and is cleared after submit.
The CLI provides the same human-only management surface:

```sh
sloosh host list
sloosh host show myhost
sloosh host add myhost --hostname server.example.com --user deploy --auth agent
sloosh host edit myhost --port 2222 --via bastion
sloosh host edit myhost --auth key-file --key-file ~/.ssh/id_ed25519
sloosh host rm myhost
sloosh vault timeout 15
```

`sloosh vault timeout` shows the current value. Setting it from either the GUI
or CLI updates both the desktop vault idle period and idle CLI/Agent leases;
per-request host approval and the 8-hour absolute lease limit remain separate.

Aliases are stable lease and ProxyJump identities, so editing cannot rename an
alias. Existing `sloosh add` and `sloosh rm` commands remain available for
compatibility. None of these commands prints authentication material.

## Build from source

Requires Rust 1.85 or newer and a working C/C++ build toolchain.

```sh
git clone https://github.com/ReiSuzunami/sloosh.git
cd sloosh
cargo build --release --locked
```

The binary is written to `target/release/sloosh`.

## License

Licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE), at your option.
