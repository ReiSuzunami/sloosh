#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

root_version="$(
  cargo metadata --no-deps --format-version 1 |
    jq -r '.packages[] | select(.name == "sloosh") | .version'
)"
desktop_version="$(
  cargo metadata --manifest-path gui/src-tauri/Cargo.toml \
    --no-deps --format-version 1 |
    jq -r '.packages[] | select(.name == "sloosh-desktop") | .version'
)"
tauri_version="$(jq -r '.version' gui/src-tauri/tauri.conf.json)"
frontend_version="$(jq -r '.version' gui/package.json)"

for candidate in "$desktop_version" "$tauri_version" "$frontend_version"; do
  if [[ "$candidate" != "$root_version" ]]; then
    printf 'version mismatch: root=%s desktop=%s tauri=%s frontend=%s\n' \
      "$root_version" "$desktop_version" "$tauri_version" \
      "$frontend_version" >&2
    exit 1
  fi
done

printf 'all package versions match: %s\n' "$root_version"
