# Installation

English | [简体中文](installation.zh-CN.md)

GitHub Releases are the primary installation channel. They provide prebuilt
binaries, so users do not need Rust or a C compiler. crates.io is a planned
secondary source-install channel for Rust users and always compiles locally.

## Prebuilt binaries

Download these files from the
[latest release](https://github.com/ReiSuzunami/sloosh/releases/latest):

| Platform | File |
|---|---|
| macOS 11 or newer, Apple silicon or Intel | `Sloosh-<version>-macos-universal.dmg` or `sloosh-macos-universal.tar.gz` |
| Linux x86_64 with readable procfs | `sloosh-linux-x86_64-musl.tar.gz` |

Download `SHA256SUMS` from the same release and verify the selected file.

macOS DMG:

```sh
version=0.1.0
dmg="Sloosh-$version-macos-universal.dmg"
grep "  $dmg$" SHA256SUMS | shasum -a 256 -c -
open "$dmg"
```

Double-click `Install Sloosh`, review the confirmation, and choose Install. The
installer copies `Sloosh.app` to Applications and creates
`~/.local/bin/sloosh` when that path is available. It then ejects the disk
image and asks whether to move the downloaded DMG to Trash. If the CLI path
already contains an unrelated file or link, the installer preserves it and
reports that the link was not changed.

The app bundle contains a Tauri desktop executable at `Contents/MacOS/Sloosh`
and the complete CLI/daemon at `Contents/Helpers/sloosh`. Keep the CLI link
pointed at that helper instead of copying it out; desktop and CLI clients both
verify that the daemon is the bundled helper executable.

macOS archive alternative:

```sh
grep '  sloosh-macos-universal.tar.gz$' SHA256SUMS | shasum -a 256 -c -
tar -xzf sloosh-macos-universal.tar.gz
install -d "$HOME/.local/bin"
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
```

Linux:

```sh
grep '  sloosh-linux-x86_64-musl.tar.gz$' SHA256SUMS | sha256sum -c -
tar -xzf sloosh-linux-x86_64-musl.tar.gz
install -d "$HOME/.local/bin"
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
```

Add `$HOME/.local/bin` to `PATH` if needed, then verify the installation:

```sh
sloosh --version
```

The macOS installer, app, and binaries are ad-hoc signed but are not currently
Developer ID signed or notarized. On first use, macOS may block the installer.
After verifying the checksum, double-click `Install Sloosh`, open System
Settings > Privacy & Security, choose Open Anyway for Install Sloosh, then
retry. This manual approval is expected for the unnotarized community build.

The Linux binary is statically linked against musl for distribution across
common Linux distributions. Sloosh still requires procfs at runtime for peer
executable and process-ancestry checks; a static binary does not remove that
requirement. Other Linux architectures currently require a source build.

## First-time setup

Run the combined setup from your own terminal:

```sh
sloosh init
```

This human-only command first installs the Agent Skill embedded in the current
binary, then creates the credential vault. A DMG installation also enrolls the
vault password in local login Keychain, gated by Touch ID and biometric
enrollment-state comparison. Before the system prompts appear, the CLI explains
the Keychain item, the `Sloosh Approval` access prompt, and one-time `Allow`
versus `Always Allow`. If the vault
already exists, rerunning `sloosh init` asks for its password once and enables
Touch ID. Source builds and the standalone CLI archive have no native helper
and keep terminal approval behavior. Linux requires no Keychain or biometric
permission; initialization prints the separate-terminal `sloosh approve <ID>`
fallback that will be used for pending leases.

Setup is safe to rerun: an existing vault is left alone. The steps are not a
transaction, so a Skill installed before a vault, daemon, or Touch ID error
remains installed and the command can be retried. Changing enrolled fingerprints
invalidates the Keychain item; rerun `sloosh init` to enroll again.

The DMG app exposes the same setup as focused native actions: Setup installs the
embedded Skill and initializes the vault; Security enables Touch ID or an
optional 6-digit PIN; Hosts manages vault-backed connection profiles. Master
Password enrollment starts with a Keychain onboarding step that explains the
stored local credential, the possible `Sloosh Approval` access prompt, and the
difference between one-time `Allow` and `Always Allow`. It also makes clear that
setup neither imports SSH private keys nor approves a host. Master
Password and PIN entry stay in the bundled native helper and never enter the
WebView. A desktop SSH Password is entered in the local Hosts form, sent as a
redacted secret, and cleared after submission. A device without Touch ID can
use PIN. Hosts can be unlocked once with Touch ID, Sloosh PIN, or Master
Password. Security offers a shared 1/5/15/30-minute vault timeout, also
available as `sloosh vault timeout [minutes]`; it governs the desktop session
and idle daemon leases without bypassing per-request approval.

By default, `--agent auto` installs for every detected agent. It uses these
locations:

| Agent | Skill directory |
|---|---|
| Codex and Agent Skills-compatible readers | `~/.agents/skills/sloosh` |
| Claude Code | `~/.claude/skills/sloosh` |

Detection treats either `~/.agents` or `~/.codex` as Codex and `~/.claude` as
Claude Code. If no agent is detected, it uses the portable Codex-compatible
path. Select explicitly with `--agent codex`, `--agent claude`, or
`--agent all`.

The standalone commands do not start the daemon or access the vault:

```sh
sloosh skill install --agent auto
sloosh skill status --agent auto
```

An unchanged Skill previously installed by sloosh upgrades with the binary.
An externally managed or locally modified Skill is preserved. Use `--force`
with `skill install`, or `--force-skill` with `init`, only when replacing it is
intentional. Sloosh never invokes `npx` or an agent marketplace; those remain
optional Skill distribution channels.

## Upgrade

Stop the running daemon before replacing the executable. Active sessions,
forwards, pending requests, and leases are in-memory and will be lost.

```sh
sloosh daemon stop
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
sloosh --version
sloosh skill install
```

For a DMG installation, open the new DMG and run `Install Sloosh`. When
replacing an existing valid installation, it stops the old daemon before the
staged replacement and leaves a matching CLI link in place. The confirmation
warns that stopping the daemon ends active sessions and forwards. If the GUI is
running, the same confirmation says it must quit; the installer requests normal
termination, waits 5 seconds, then force quits only under that explicit consent.
Replacement never starts while the old GUI is still running.

This order also avoids the old daemon continuing from a replaced executable on
Linux, where the new CLI correctly refuses an unverifiable `/proc/<pid>/exe`
peer.

If an in-place replacement already left the old Linux daemon shown as
`(deleted)` and CLI refuses its socket, locate it with
`pgrep -u "$(id -u)" -af 'sloosh daemon run'`. Confirm the process, run
`kill <pid>`, then retry; CLI will remove the stale socket and start the new
binary.

## Install from crates.io

After the first crate publish, this path downloads source and compiles it. It
requires Rust 1.85 or newer and a working C/C++ build toolchain:

```sh
cargo install sloosh --locked
```

The installed binary normally lands in `$HOME/.cargo/bin`. crates.io is useful
for Rust developers, but it is not the no-build installation path.

For a repository checkout, follow the concise
[source-build steps in the README](../../README.md#build-from-source).
