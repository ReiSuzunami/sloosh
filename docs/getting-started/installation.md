# Installation

English | [简体中文](installation.zh-CN.md)

GitHub Releases are the primary installation channel once a release is
available. They provide prebuilt binaries, so users do not need Rust or a C
compiler. If the latest-release page has no version yet, use the source-build
steps below. crates.io is a secondary source-install channel for Rust
users and always compiles locally. The Homebrew tap and crates.io install the
command-line package (`sloosh` plus its companion `slooshd`); the desktop app
and DMG are distributed only through GitHub Releases.

## Prebuilt binaries

When available, download these files from the
[latest release](https://github.com/ReiSuzunami/sloosh/releases/latest):

| Platform | File |
|---|---|
| macOS 11 or newer, Apple silicon or Intel | `Sloosh-<version>-macos-universal.dmg` or `sloosh-macos-universal.tar.gz` |
| Linux x86_64 with readable procfs | `sloosh-linux-x86_64-musl.tar.gz` |

Download `SHA256SUMS` from the same release and verify the selected file.

macOS DMG:

```sh
version=0.2.3
dmg="Sloosh-$version-macos-universal.dmg"
grep "  $dmg$" SHA256SUMS | shasum -a 256 -c -
open "$dmg"
```

Double-click `Install Sloosh`, review the confirmation, and choose Install. The
installer stops any running sloosh daemon before copying `Sloosh.app` to
Applications, including one started earlier by Homebrew, Cargo, an archive, or
a source build. Stopping ends active sessions and forwards. The installer does
not install a public CLI or create anything in `PATH`. During an upgrade from
the original combined bundle, it removes only a `~/.local/bin/sloosh` symlink
whose stored destination is exactly the old helper inside that same app; every
unrelated file or link is preserved. It then ejects the disk image and asks
whether to move the downloaded DMG to Trash.

The app bundle contains a Tauri desktop executable at `Contents/MacOS/Sloosh`
and a private daemon at `Contents/Helpers/slooshd`. It deliberately contains no
public `sloosh` executable. The desktop connects directly to this daemon over
the local protocol rather than shelling out to a CLI.

macOS archive alternative:

```sh
grep '  sloosh-macos-universal.tar.gz$' SHA256SUMS | shasum -a 256 -c -
tar -xzf sloosh-macos-universal.tar.gz
install -d "$HOME/.local/bin"
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
install -m 0755 sloosh-*/slooshd "$HOME/.local/bin/slooshd"
```

Linux:

```sh
grep '  sloosh-linux-x86_64-musl.tar.gz$' SHA256SUMS | sha256sum -c -
tar -xzf sloosh-linux-x86_64-musl.tar.gz
install -d "$HOME/.local/bin"
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
install -m 0755 sloosh-*/slooshd "$HOME/.local/bin/slooshd"
```

Add `$HOME/.local/bin` to `PATH` if needed, then verify the installation:

```sh
sloosh --version
slooshd --version
```

`slooshd` is managed by the client and desktop app; do not start it directly
during ordinary use.

GitHub Release macOS artifacts use a fixed self-signed project certificate so
their code identity remains stable across updates. They are not Developer ID
signed or notarized, and the certificate is not added to system trust. On first
use, macOS may block the installer. After verifying the checksum, double-click
`Install Sloosh`, open System Settings > Privacy & Security, choose Open Anyway
for Install Sloosh, then retry. This manual approval is expected for the
unnotarized community build. The first upgrade from an older ad-hoc build
requires native approval enrollment once; later releases signed by the same
certificate keep the same Keychain identity. Local source builds still default
to ad-hoc signing unless a signing identity is configured.

The Linux binary is statically linked against musl for distribution across
common Linux distributions. Sloosh still requires procfs at runtime for peer
executable and process-ancestry checks; a static binary does not remove that
requirement. Other Linux architectures currently require a source build.

## First-time setup

Run the combined setup from your own terminal:

```sh
sloosh init
```

This human-only command first installs the Agent Skill embedded in the client,
then creates the credential vault. Command-line-only installations use terminal
approval; Linux requires no Keychain or biometric permission and initialization
prints the separate-terminal `sloosh approve <ID>` fallback.

The desktop app owns native setup. Open its Setup and Security screens to
initialize or unlock the same vault and enroll the vault password in the login
Keychain behind Touch ID or the optional local PIN. The separately distributed
CLI never executes the native helper directly. When the app is installed in
Applications, both clients use its private daemon, so CLI lease requests can
still complete through native approval after the human has enrolled it in the
app. `Always Allow` avoids repeated Keychain prompts; `Allow` grants one-time
access.

Setup is safe to rerun: an existing vault is left alone. The steps are not a
transaction, so a Skill installed before a vault, daemon, or Touch ID error
remains installed and the command can be retried. Changing enrolled fingerprints
invalidates the Keychain item; rerun `sloosh init` to enroll again.

The DMG app exposes setup as focused native actions: Setup installs the
embedded Skill and initializes the vault; Security configures native unlock and
the shared timeout; Hosts manages connection profiles. Setup neither imports
SSH private keys nor approves a host. Continue with the
[desktop app section of the manual](../manual.md#desktop-app).

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
install -m 0755 sloosh-*/slooshd "$HOME/.local/bin/slooshd"
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
sloosh --version
sloosh skill install
```

For a DMG installation, open the new DMG and run `Install Sloosh`. On both a
fresh install and an upgrade, it stops any daemon already using the shared
socket before installing the app helper. It removes the exact legacy
DMG-created CLI symlink but does not touch a Homebrew, Cargo, archive, or
user-managed CLI. The confirmation warns that stopping the daemon ends active
sessions and forwards. If the GUI is running, the same confirmation says it
must quit; the installer requests normal termination, waits 5 seconds, then
force quits only under that explicit consent. Replacement never starts while
the old GUI is still running.

This order also avoids the old daemon continuing from a replaced executable on
Linux, where the new CLI correctly refuses an unverifiable `/proc/<pid>/exe`
peer.

If an in-place replacement already left the old Linux daemon shown as
`(deleted)` and CLI refuses its socket, locate it with
`pgrep -u "$(id -u)" -af 'slooshd'`. Confirm the executable path, run
`kill <pid>`, then retry; CLI will remove the stale socket and start the new
daemon.

## CLI package managers

Homebrew installs the prebuilt command-line package from the project tap:

```sh
brew install ReiSuzunami/tap/sloosh
```

The formula installs both `sloosh` and its managed `slooshd`; it does not
install the desktop app or generate a DMG.

crates.io can instead download the source and compile the command-line package
locally. This requires Rust 1.85 or newer and a working C/C++ toolchain:

```sh
cargo install sloosh --locked
```

Both binaries normally land in `$HOME/.cargo/bin`. The crate does not
contain the Tauri desktop source, macOS installer, or DMG packaging resources,
so it cannot build the Sloosh DMG. crates.io is useful for Rust developers, but
it is not the no-build installation path.

For a repository checkout, follow the concise
[source-build steps in the README](../../README.en.md#build-from-source).
After installation, continue with the [manual](../manual.md).
