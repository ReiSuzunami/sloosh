# Installation

GitHub Releases are the primary installation channel. They provide prebuilt
binaries, so users do not need Rust or a C compiler. crates.io is a planned
secondary source-install channel for Rust users and always compiles locally.

## Prebuilt binaries

Download these files from the
[latest release](https://github.com/ReiSuzunami/sloosh/releases/latest):

| Platform | Archive |
|---|---|
| macOS 11 or newer, Apple silicon or Intel | `sloosh-macos-universal.tar.gz` |
| Linux x86_64 with readable procfs | `sloosh-linux-x86_64-musl.tar.gz` |

Download `SHA256SUMS` from the same release and verify the selected archive.

macOS:

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

The macOS binary is ad-hoc signed but is not currently Developer ID signed or
notarized. Verify its checksum before approving any operating-system prompt.

The Linux binary is statically linked against musl for distribution across
common Linux distributions. Sloosh still requires procfs at runtime for peer
executable and process-ancestry checks; a static binary does not remove that
requirement. Other Linux architectures currently require a source build.

## Upgrade

Stop the running daemon before replacing the executable. Active sessions,
forwards, pending requests, and leases are in-memory and will be lost.

```sh
sloosh daemon stop
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
sloosh --version
```

This order also avoids the old daemon continuing from a replaced executable on
Linux, where the new CLI correctly refuses an unverifiable `/proc/<pid>/exe`
peer.

## Install from crates.io

After the first crate publish, this path downloads source and compiles it. It
requires Rust 1.85 or newer and a working C/C++ build toolchain:

```sh
cargo install sloosh --locked
```

The installed binary normally lands in `$HOME/.cargo/bin`. crates.io is useful
for Rust developers, but it is not the no-build installation path.

## Build from a checkout

```sh
git clone https://github.com/ReiSuzunami/sloosh
cd sloosh
cargo build --release --locked
```

The binary is `target/release/sloosh`.
