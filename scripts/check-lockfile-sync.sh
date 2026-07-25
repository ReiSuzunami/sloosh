#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

package_records() {
  local lockfile="$1"
  local package="$2"

  awk -v package="$package" '
    function value(line) {
      sub(/^[^=]+=[[:space:]]*"/, "", line)
      sub(/"$/, "", line)
      return line
    }
    function emit() {
      if (name == package) {
        print name "\t" version "\t" source "\t" checksum
      }
    }
    $0 == "[[package]]" {
      emit()
      name = version = source = checksum = ""
      next
    }
    /^name = "/ { name = value($0); next }
    /^version = "/ { version = value($0); next }
    /^source = "/ { source = value($0); next }
    /^checksum = "/ { checksum = value($0); next }
    END { emit() }
  ' "$lockfile" | LC_ALL=C sort
}

# The desktop manifest consumes the root crate through a path dependency.
# Dependabot can update Cargo.lock without refreshing gui/src-tauri/Cargo.lock,
# leaving a vulnerable SSH runtime version in the desktop build.
for package in russh russh-sftp; do
  root_records="$(package_records Cargo.lock "$package")"
  desktop_records="$(package_records gui/src-tauri/Cargo.lock "$package")"

  if [[ -z "$root_records" || -z "$desktop_records" ]]; then
    printf 'missing %s package in root or desktop lockfile\n' \
      "$package" >&2
    exit 1
  fi

  if [[ "$root_records" != "$desktop_records" ]]; then
    printf '%s package identity mismatch between lockfiles\n' \
      "$package" >&2
    printf 'root: %s\ndesktop: %s\n' \
      "$root_records" "$desktop_records" >&2
    exit 1
  fi
done

printf 'security-sensitive SSH lockfile versions match\n'
