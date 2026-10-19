#!/usr/bin/env bash
# Idempotent Cloud Agent bootstrap for sloosh.
#
# Prepares everything the CONTRIBUTING.md gate needs: the Rust CLI/daemon
# (MSRV 1.85 plus current stable), the Tauri desktop crate and its Linux
# system libraries, the pnpm-managed Svelte frontend, and cargo-deny for the
# dependency-policy checks. Safe to run repeatedly and against cached state.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

log() { printf '\n=== %s ===\n' "$1"; }

SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
fi

# 1. System libraries for the Tauri desktop crate (webkit2gtk, gtk, appindicator,
#    rsvg, xdo) plus the C/C++ toolchain and OpenSSL headers russh links against.
log "system packages"
export DEBIAN_FRONTEND=noninteractive
$SUDO apt-get update -qq
$SUDO apt-get install -y --no-install-recommends \
  build-essential \
  pkg-config \
  file \
  libssl-dev \
  libgtk-3-dev \
  libwebkit2gtk-4.1-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  libxdo-dev

# 2. Rust toolchains. Root CLI/daemon keeps MSRV 1.85; the isolated Tauri crate
#    (rust-version 1.88) and the gate's lint/build use current stable.
log "rust toolchains"
rustup toolchain install stable --profile minimal --component rustfmt,clippy
rustup toolchain install 1.85.0 --profile minimal --component rustfmt,clippy
rustup default stable

# 3. cargo-deny for the advisories/bans/licenses/sources policy gate.
log "cargo-deny"
if ! command -v cargo-deny >/dev/null 2>&1; then
  cargo +stable install cargo-deny --locked
fi

# 4. pnpm pinned by gui/package.json (packageManager), via corepack.
log "pnpm / frontend deps"
corepack enable
corepack prepare pnpm@11.8.0 --activate
pnpm --dir gui install --frozen-lockfile

# 5. Warm the workspace build so the first gate run is fast.
log "warm cargo build"
cargo build --bins --locked

log "install complete"
