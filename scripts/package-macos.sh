#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: $0 <version> <universal-slooshd> <universal-sloosh-gui> <output-directory>" >&2
  exit 2
}

[[ $# -eq 4 ]] || usage

version="$1"
daemon_binary="$2"
gui_binary="$3"
output_dir="$4"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || {
  echo "invalid version: $version" >&2
  exit 2
}
[[ -f "$daemon_binary" && -x "$daemon_binary" ]] || {
  echo "universal daemon is missing or not executable: $daemon_binary" >&2
  exit 2
}
[[ -f "$gui_binary" && -x "$gui_binary" ]] || {
  echo "universal GUI binary is missing or not executable: $gui_binary" >&2
  exit 2
}
[[ "$(uname -s)" == "Darwin" ]] || {
  echo "macOS packaging requires Darwin" >&2
  exit 2
}

for command in codesign ditto hdiutil iconutil lipo mount osascript plutil sips swift xcrun; do
  command -v "$command" >/dev/null || {
    echo "required command not found: $command" >&2
    exit 2
  }
done

signing_identity="${SLOOSH_MACOS_SIGNING_IDENTITY:--}"
signing_keychain="${SLOOSH_MACOS_SIGNING_KEYCHAIN:-}"
if [[ -n "$signing_keychain" && ! -f "$signing_keychain" ]]; then
  echo "macOS signing keychain does not exist: $signing_keychain" >&2
  exit 2
fi

sign_code() {
  local target="$1"
  local arguments=(--force --sign "$signing_identity" --timestamp=none)
  if [[ -n "$signing_keychain" ]]; then
    arguments+=(--keychain "$signing_keychain")
  fi
  codesign "${arguments[@]}" "$target"
}

verify_stable_signing_requirement() {
  local target="$1"
  [[ "$signing_identity" != "-" ]] || return 0

  local requirement
  requirement="$(codesign -d -r- "$target" 2>&1)" || {
    echo "could not inspect signing requirement for $target" >&2
    exit 1
  }
  if grep -Eq 'designated => .*cdhash' <<<"$requirement"; then
    echo "configured signing identity produced an ad-hoc cdhash requirement: $target" >&2
    exit 1
  fi
}

if [[ "$signing_identity" == "-" ]]; then
  echo "macOS signing mode: ad-hoc"
else
  echo "macOS signing identity: $signing_identity"
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"
daemon_binary="$(cd -- "$(dirname -- "$daemon_binary")" && pwd -P)/$(basename -- "$daemon_binary")"
gui_binary="$(cd -- "$(dirname -- "$gui_binary")" && pwd -P)/$(basename -- "$gui_binary")"
mkdir -p "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd -P)"

tmp_dir="$(mktemp -d)"
mount_dir="$tmp_dir/mount"
mounted_path="$mount_dir"
mounted=0
mounted_installer=""
test_gui_started=0
running_gui_home=""
simulated_install=""
test_daemon_pid=""

cleanup() {
  if [[ -n "$test_daemon_pid" ]]; then
    kill "$test_daemon_pid" >/dev/null 2>&1 || true
    wait "$test_daemon_pid" >/dev/null 2>&1 || true
  fi
  if [[ "$test_gui_started" -eq 1 && -x "$mounted_installer/Contents/MacOS/install-sloosh" ]]; then
    env SLOOSH_INSTALLER_TEST_MODE=1 \
      "$mounted_installer/Contents/MacOS/install-sloosh" \
        --test-stop-application "$simulated_install" >/dev/null 2>&1 || true
    if [[ -n "$running_gui_home" && -S "$running_gui_home/.sloosh/sloosh.sock" ]]; then
      env SLOOSH_INSTALLER_TEST_MODE=1 \
        "$mounted_installer/Contents/MacOS/install-sloosh" \
          --test-shutdown "$running_gui_home" >/dev/null 2>&1 || true
    fi
  fi
  if [[ "$mounted" -eq 1 ]]; then
    hdiutil detach "$mounted_path" >/dev/null 2>&1 ||
      hdiutil detach -force "$mounted_path" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

app="$tmp_dir/Sloosh.app"
contents="$app/Contents"
installer="$tmp_dir/Install Sloosh.app"
installer_contents="$installer/Contents"
icon_source="$repo_root/packaging/macos/AppIcon.png"
icon_validator_source="$repo_root/packaging/macos/validate-app-icon.swift"
adaptive_icon_source="$repo_root/packaging/macos/Sloosh.icon"
iconset="$tmp_dir/Sloosh.iconset"
adaptive_icon_output="$tmp_dir/adaptive-icon"
adaptive_icon_plist="$tmp_dir/adaptive-icon.plist"
background_generator="$repo_root/packaging/macos/render-dmg-background.swift"
layout_script="$repo_root/packaging/macos/layout-dmg.applescript"
installer_source="$repo_root/packaging/macos/install-sloosh.swift"
installer_info="$repo_root/packaging/macos/InstallInfo.plist"
approval_source="$repo_root/packaging/macos/native-approval.swift"
approval_info="$repo_root/packaging/macos/NativeApprovalInfo.plist"
approval_app="$contents/Helpers/Sloosh Approval.app"
approval_contents="$approval_app/Contents"
stage="$tmp_dir/stage"
background="$stage/.background/background.png"
rw_dmg="$tmp_dir/Sloosh-rw.dmg"
dmg="$output_dir/Sloosh-$version-macos-universal.dmg"
volume_name="Sloosh $version"
marketing_version="${version%%[-+]*}"

mkdir -p "$contents/MacOS" "$contents/Helpers" "$contents/Resources" "$stage"
install -m 0755 "$gui_binary" "$contents/MacOS/Sloosh"
install -m 0755 "$daemon_binary" "$contents/Helpers/slooshd"
install -m 0644 "$repo_root/packaging/macos/Info.plist" "$contents/Info.plist"
install -m 0644 "$repo_root/LICENSE-APACHE" "$repo_root/LICENSE-MIT" \
  "$contents/Resources/"

icon_width="$(sips -g pixelWidth "$icon_source" | awk '$1 == "pixelWidth:" { print $2 }')"
icon_height="$(sips -g pixelHeight "$icon_source" | awk '$1 == "pixelHeight:" { print $2 }')"
icon_alpha="$(sips -g hasAlpha "$icon_source" | awk '$1 == "hasAlpha:" { print $2 }')"
[[ "$icon_width" == "1024" && "$icon_height" == "1024" && "$icon_alpha" == "yes" ]] || {
  echo "AppIcon.png must be a 1024x1024 PNG with alpha" >&2
  exit 1
}
xcrun swiftc -swift-version 5 -O "$icon_validator_source" \
  -framework CoreGraphics -framework ImageIO \
  -o "$tmp_dir/validate-app-icon"
"$tmp_dir/validate-app-icon" "$icon_source"

mkdir -p "$iconset"
while read -r pixels filename; do
  sips -z "$pixels" "$pixels" "$icon_source" \
    --out "$iconset/$filename" >/dev/null
done <<'ICON_SIZES'
16 icon_16x16.png
32 icon_16x16@2x.png
32 icon_32x32.png
64 icon_32x32@2x.png
128 icon_128x128.png
256 icon_128x128@2x.png
256 icon_256x256.png
512 icon_256x256@2x.png
512 icon_512x512.png
1024 icon_512x512@2x.png
ICON_SIZES
iconutil -c icns "$iconset" -o "$contents/Resources/Sloosh.icns"
[[ -s "$contents/Resources/Sloosh.icns" ]]

mkdir -p "$adaptive_icon_output"
if xcrun actool \
  --compile "$adaptive_icon_output" \
  --platform macosx \
  --target-device mac \
  --minimum-deployment-target 11.0 \
  --app-icon Sloosh \
  --standalone-icon-behavior all \
  --output-partial-info-plist "$adaptive_icon_plist" \
  "$adaptive_icon_source" >"$tmp_dir/actool.log" 2>&1 &&
  [[ -s "$adaptive_icon_output/Assets.car" ]] &&
  [[ -s "$adaptive_icon_output/Sloosh.icns" ]]; then
  install -m 0644 "$adaptive_icon_output/Assets.car" \
    "$contents/Resources/Assets.car"
  install -m 0644 "$adaptive_icon_output/Sloosh.icns" \
    "$contents/Resources/Sloosh.icns"
  /usr/libexec/PlistBuddy -c "Add :CFBundleIconName string Sloosh" \
    "$contents/Info.plist"
else
  echo "adaptive app icon output is unavailable or incomplete; using static ICNS fallback" >&2
  sed 's/^/actool: /' "$tmp_dir/actool.log" >&2
fi

/usr/libexec/PlistBuddy -c \
  "Set :CFBundleShortVersionString $marketing_version" "$contents/Info.plist"
/usr/libexec/PlistBuddy -c \
  "Set :CFBundleVersion $marketing_version" "$contents/Info.plist"
/usr/libexec/PlistBuddy -c \
  "Set :SlooshVersion $version" "$contents/Info.plist"
plutil -lint "$contents/Info.plist" >/dev/null

for bundled_binary in "$contents/MacOS/Sloosh" "$contents/Helpers/slooshd"; do
  archs="$(
  lipo -archs "$bundled_binary" |
    tr ' ' '\n' |
    LC_ALL=C sort |
    paste -sd ' ' -
  )"
  [[ "$archs" == "arm64 x86_64" ]] || {
    echo "expected arm64 and x86_64 slices in $bundled_binary, got: $archs" >&2
    exit 1
  }
done

for bundled_binary in "$contents/MacOS/Sloosh" "$contents/Helpers/slooshd"; do
  minos_values="$(
  xcrun vtool -show-build "$bundled_binary" |
    awk '$1 == "minos" { print $2 }'
  )"
  [[ -n "$minos_values" ]] || {
    echo "could not read LC_BUILD_VERSION minimum OS for $bundled_binary" >&2
    exit 1
  }
  if echo "$minos_values" | grep -Ev '^11\.0(\.0)?$' >/dev/null; then
    echo "all slices in $bundled_binary must target macOS 11.0; got:" >&2
    echo "$minos_values" >&2
    exit 1
  fi
done

test "$("$contents/Helpers/slooshd" --version)" = "slooshd $version"
sdk_path="$(xcrun --sdk macosx --show-sdk-path)"
for arch in arm64 x86_64; do
  xcrun swiftc \
    -swift-version 5 \
    -O \
    -target "$arch-apple-macos11.0" \
    -sdk "$sdk_path" \
    "$approval_source" \
    -o "$tmp_dir/sloosh-approval-$arch"
done

mkdir -p "$approval_contents/MacOS" "$approval_contents/Resources"
lipo -create \
  "$tmp_dir/sloosh-approval-arm64" \
  "$tmp_dir/sloosh-approval-x86_64" \
  -output "$approval_contents/MacOS/sloosh-approval"
chmod 0755 "$approval_contents/MacOS/sloosh-approval"
install -m 0644 "$approval_info" "$approval_contents/Info.plist"
install -m 0644 "$contents/Resources/Sloosh.icns" \
  "$approval_contents/Resources/Sloosh.icns"
/usr/libexec/PlistBuddy -c \
  "Set :CFBundleShortVersionString $marketing_version" "$approval_contents/Info.plist"
/usr/libexec/PlistBuddy -c \
  "Set :CFBundleVersion $marketing_version" "$approval_contents/Info.plist"
plutil -lint "$approval_contents/Info.plist" >/dev/null

approval_archs="$(
  lipo -archs "$approval_contents/MacOS/sloosh-approval" |
    tr ' ' '\n' |
    LC_ALL=C sort |
    paste -sd ' ' -
)"
[[ "$approval_archs" == "arm64 x86_64" ]] || {
  echo "expected universal native approval helper, got: $approval_archs" >&2
  exit 1
}
sign_code "$approval_contents/MacOS/sloosh-approval"
sign_code "$approval_app"
sign_code "$contents/Helpers/slooshd"
sign_code "$contents/MacOS/Sloosh"
sign_code "$app"
codesign --verify --deep --strict --verbose=2 "$app"
verify_stable_signing_requirement \
  "$approval_contents/MacOS/sloosh-approval"
verify_stable_signing_requirement "$contents/Helpers/slooshd"
verify_stable_signing_requirement "$contents/MacOS/Sloosh"
verify_stable_signing_requirement "$app"

for arch in arm64 x86_64; do
  xcrun swiftc \
    -swift-version 5 \
    -O \
    -target "$arch-apple-macos11.0" \
    -sdk "$sdk_path" \
    "$installer_source" \
    -o "$tmp_dir/install-sloosh-$arch"
done

mkdir -p "$installer_contents/MacOS" "$installer_contents/Helpers" \
  "$installer_contents/Resources"
lipo -create \
  "$tmp_dir/install-sloosh-arm64" \
  "$tmp_dir/install-sloosh-x86_64" \
  -output "$installer_contents/MacOS/install-sloosh"
chmod 0755 "$installer_contents/MacOS/install-sloosh"
ditto "$app" "$installer_contents/Helpers/Sloosh.app"
install -m 0644 "$contents/Resources/Sloosh.icns" \
  "$installer_contents/Resources/Sloosh.icns"
install -m 0644 "$installer_info" "$installer_contents/Info.plist"
if [[ -s "$contents/Resources/Assets.car" ]]; then
  install -m 0644 "$contents/Resources/Assets.car" \
    "$installer_contents/Resources/Assets.car"
  /usr/libexec/PlistBuddy -c "Add :CFBundleIconName string Sloosh" \
    "$installer_contents/Info.plist"
fi
/usr/libexec/PlistBuddy -c \
  "Set :CFBundleShortVersionString $marketing_version" "$installer_contents/Info.plist"
/usr/libexec/PlistBuddy -c \
  "Set :CFBundleVersion $marketing_version" "$installer_contents/Info.plist"
plutil -lint "$installer_contents/Info.plist" >/dev/null

installer_archs="$(
  lipo -archs "$installer_contents/MacOS/install-sloosh" |
    tr ' ' '\n' |
    LC_ALL=C sort |
    paste -sd ' ' -
)"
[[ "$installer_archs" == "arm64 x86_64" ]] || {
  echo "expected universal installer, got: $installer_archs" >&2
  exit 1
}
installer_minos_values="$(
  xcrun vtool -show-build "$installer_contents/MacOS/install-sloosh" |
    awk '$1 == "minos" { print $2 }'
)"
[[ -n "$installer_minos_values" ]] || {
  echo "could not read installer LC_BUILD_VERSION minimum OS" >&2
  exit 1
}
if echo "$installer_minos_values" | grep -Ev '^11\.0(\.0)?$' >/dev/null; then
  echo "all installer slices must target macOS 11.0; got:" >&2
  echo "$installer_minos_values" >&2
  exit 1
fi

sign_code "$installer_contents/MacOS/install-sloosh"
sign_code "$installer"
codesign --verify --deep --strict --verbose=2 "$installer"
verify_stable_signing_requirement \
  "$installer_contents/MacOS/install-sloosh"
verify_stable_signing_requirement "$installer"

ditto "$installer" "$stage/Install Sloosh.app"
mkdir -p "$(dirname "$background")"
swift "$background_generator" "$background"
touch "$stage/.metadata_never_index"

background_width="$(sips -g pixelWidth "$background" | awk '$1 == "pixelWidth:" { print $2 }')"
background_height="$(sips -g pixelHeight "$background" | awk '$1 == "pixelHeight:" { print $2 }')"
[[ "$background_width" == "1440" && "$background_height" == "880" ]] || {
  echo "DMG background must be 1440x880 for Retina displays" >&2
  exit 1
}

rm -f "$dmg"
hdiutil create \
  -volname "$volume_name" \
  -srcfolder "$stage" \
  -fs HFS+ \
  -format UDRW \
  -ov \
  "$rw_dmg" >/dev/null

layout_mount_dir="/Volumes/$volume_name"
[[ ! -e "$layout_mount_dir" ]] || {
  echo "volume is already mounted: $layout_mount_dir" >&2
  exit 1
}
hdiutil attach -nobrowse -readwrite "$rw_dmg" >/dev/null
mounted_path="$layout_mount_dir"
mounted=1
layout_ready=0
for _ in {1..10}; do
  if osascript "$layout_script" "$volume_name"; then
    layout_ready=1
    break
  fi
  sleep 1
done
[[ "$layout_ready" -eq 1 ]] || {
  echo "Finder did not expose the mounted volume for layout: $volume_name" >&2
  exit 1
}
[[ -s "$layout_mount_dir/.DS_Store" ]]
[[ -s "$layout_mount_dir/.background/background.png" ]]
hdiutil detach "$layout_mount_dir" >/dev/null
mounted=0

hdiutil convert "$rw_dmg" \
  -format UDZO \
  -imagekey zlib-level=9 \
  -ov \
  -o "$dmg" >/dev/null
hdiutil verify "$dmg" >/dev/null

mkdir -p "$mount_dir"
mount_probe_path="$(cd -- "$mount_dir" && pwd -P)"
hdiutil attach -nobrowse -readonly -mountpoint "$mount_dir" "$dmg" >/dev/null
mounted_path="$mount_dir"
mounted=1

mounted_installer="$mount_dir/Install Sloosh.app"
mounted_app="$mounted_installer/Contents/Helpers/Sloosh.app"
[[ -d "$mounted_installer" ]]
[[ -d "$mounted_app" ]]
[[ -s "$mount_dir/.DS_Store" ]]
[[ -s "$mount_dir/.background/background.png" ]]
test "$(sips -g pixelWidth "$mount_dir/.background/background.png" |
  awk '$1 == "pixelWidth:" { print $2 }')" = "1440"
test "$(sips -g pixelHeight "$mount_dir/.background/background.png" |
  awk '$1 == "pixelHeight:" { print $2 }')" = "880"
test "$(plutil -extract CFBundleIconFile raw \
  "$mounted_app/Contents/Info.plist")" = "Sloosh.icns"
[[ -s "$mounted_app/Contents/Resources/Sloosh.icns" ]]
if [[ -s "$mounted_app/Contents/Resources/Assets.car" ]]; then
  test "$(plutil -extract CFBundleIconName raw \
    "$mounted_app/Contents/Info.plist")" = "Sloosh"
  [[ -s "$mounted_installer/Contents/Resources/Assets.car" ]]
  test "$(plutil -extract CFBundleIconName raw \
    "$mounted_installer/Contents/Info.plist")" = "Sloosh"
fi
[[ -x "$mounted_app/Contents/Helpers/Sloosh Approval.app/Contents/MacOS/sloosh-approval" ]]
test "$(plutil -extract CFBundleIdentifier raw \
  "$mounted_app/Contents/Helpers/Sloosh Approval.app/Contents/Info.plist")" = \
  "io.github.reisuzunami.sloosh.approval"
test "$(plutil -extract CFBundleIconFile raw \
  "$mounted_app/Contents/Helpers/Sloosh Approval.app/Contents/Info.plist")" = \
  "Sloosh.icns"
[[ -s "$mounted_app/Contents/Helpers/Sloosh Approval.app/Contents/Resources/Sloosh.icns" ]]
test "$("$mounted_app/Contents/Helpers/slooshd" --version)" = "slooshd $version"
[[ ! -e "$mounted_app/Contents/Helpers/sloosh" ]]
test "$(plutil -extract CFBundleExecutable raw \
  "$mounted_app/Contents/Info.plist")" = "Sloosh"
test "$(
  lipo -archs "$mounted_app/Contents/MacOS/Sloosh" |
    tr ' ' '\n' |
    LC_ALL=C sort |
    paste -sd ' ' -
)" = "arm64 x86_64"
test "$(plutil -extract CFBundleDisplayName raw \
  "$mounted_installer/Contents/Info.plist")" = "Install Sloosh"
test "$(
  lipo -archs "$mounted_installer/Contents/MacOS/install-sloosh" |
    tr ' ' '\n' |
    LC_ALL=C sort |
    paste -sd ' ' -
)" = "arm64 x86_64"
codesign --verify --deep --strict --verbose=2 "$mounted_app"
codesign --verify --deep --strict --verbose=2 "$mounted_installer"

reported_dmg="$(
  env SLOOSH_INSTALLER_TEST_MODE=1 \
    "$mounted_installer/Contents/MacOS/install-sloosh" \
    --test-image-path "$mount_dir"
)"
reported_dmg="$(
  cd -- "$(dirname -- "$reported_dmg")"
  printf '%s/%s\n' "$(pwd -P)" "$(basename -- "$reported_dmg")"
)"
test "$reported_dmg" = "$dmg"

simulated_install="$tmp_dir/Applications/Sloosh.app"
simulated_home="$tmp_dir/home"
fresh_sibling="$tmp_dir/fresh-sibling/slooshd"
mkdir -p "$simulated_home" "$(dirname "$fresh_sibling")"
cp "$mounted_app/Contents/Helpers/slooshd" "$fresh_sibling"
chmod 0755 "$fresh_sibling"
SLOOSH_HOME="$simulated_home/.sloosh" \
  "$fresh_sibling" >"$tmp_dir/fresh-sibling-daemon.log" 2>&1 &
test_daemon_pid=$!
for _ in {1..100}; do
  [[ -S "$simulated_home/.sloosh/sloosh.sock" ]] && break
  sleep 0.05
done
test -S "$simulated_home/.sloosh/sloosh.sock"
env SLOOSH_INSTALLER_TEST_MODE=1 \
  "$mounted_installer/Contents/MacOS/install-sloosh" \
  --test-install "$(dirname "$simulated_install")" "$simulated_home"
for _ in {1..100}; do
  [[ -e "$simulated_home/.sloosh/sloosh.sock" ]] || break
  sleep 0.05
done
[[ ! -e "$simulated_home/.sloosh/sloosh.sock" ]] || {
  echo "fresh install did not stop the existing sibling daemon" >&2
  exit 1
}
wait "$test_daemon_pid"
test_daemon_pid=""
codesign --verify --deep --strict --verbose=2 "$simulated_install"
test "$("$simulated_install/Contents/Helpers/slooshd" --version)" = "slooshd $version"
[[ ! -e "$simulated_install/Contents/Helpers/sloosh" ]]
[[ ! -e "$simulated_home/.local/bin/sloosh" ]]
[[ ! -L "$simulated_home/.local/bin/sloosh" ]]

# A second run exercises the staged upgrade path and removes only the exact
# CLI link created by the legacy DMG.
mkdir -p "$simulated_home/.local/bin"
ln -s "$simulated_install/Contents/Helpers/sloosh" \
  "$simulated_home/.local/bin/sloosh"
upgrade_output="$(
  env SLOOSH_INSTALLER_TEST_MODE=1 \
    "$mounted_installer/Contents/MacOS/install-sloosh" \
    --test-install "$(dirname "$simulated_install")" "$simulated_home"
)"
grep -F "Removed the legacy DMG CLI link at ~/.local/bin/sloosh." \
  <<<"$upgrade_output" >/dev/null
[[ ! -e "$simulated_home/.local/bin/sloosh" ]]
[[ ! -L "$simulated_home/.local/bin/sloosh" ]]
codesign --verify --deep --strict --verbose=2 "$simulated_install"

# A staged replacement failure restores the exact previous application and
# removes both transient siblings.
rollback_inode="$(stat -f '%i' "$simulated_install")"
env SLOOSH_INSTALLER_TEST_MODE=1 \
  "$mounted_installer/Contents/MacOS/install-sloosh" \
  --test-install-rollback "$(dirname "$simulated_install")" "$simulated_home"
test "$(stat -f '%i' "$simulated_install")" = "$rollback_inode"
codesign --verify --deep --strict --verbose=2 "$simulated_install"
if find "$(dirname "$simulated_install")" -maxdepth 1 \
  \( -name '.Sloosh.installing-*.app' -o -name '.Sloosh.backup-*.app' \) \
  -print -quit | grep -q .; then
  echo "installer rollback left a staged or backup application behind" >&2
  exit 1
fi

# A v0.1.0 GUI + full-CLI helper remains a recognized upgrade target.
legacy_home="$tmp_dir/legacy-home"
legacy_applications="$tmp_dir/legacy-Applications"
legacy_install="$legacy_applications/Sloosh.app"
mkdir -p "$legacy_home/.local/bin" "$legacy_applications"
ditto "$simulated_install" "$legacy_install"
mv "$legacy_install/Contents/Helpers/slooshd" \
  "$legacy_install/Contents/Helpers/sloosh"
ln -s "$legacy_install/Contents/Helpers/sloosh" \
  "$legacy_home/.local/bin/sloosh"
env SLOOSH_INSTALLER_TEST_MODE=1 \
  "$mounted_installer/Contents/MacOS/install-sloosh" \
  --test-install "$legacy_applications" "$legacy_home"
codesign --verify --deep --strict --verbose=2 "$legacy_install"
[[ -x "$legacy_install/Contents/Helpers/slooshd" ]]
[[ ! -e "$legacy_install/Contents/Helpers/sloosh" ]]
[[ ! -L "$legacy_home/.local/bin/sloosh" ]]

# Updating a running GUI first asks it to terminate, escalates to force-quit
# after a bounded wait, and never targets another bundle path with the same ID.
running_gui_home="$tmp_dir/running-gui-home"
mkdir -p "$running_gui_home/.sloosh"
open -n -g \
  --env "SLOOSH_HOME=$running_gui_home/.sloosh" \
  --stdout "$tmp_dir/running-gui.log" \
  --stderr "$tmp_dir/running-gui.log" \
  "$simulated_install"
test_gui_started=1
running_count=0
for _ in {1..100}; do
  running_count="$(
    env SLOOSH_INSTALLER_TEST_MODE=1 \
      "$mounted_installer/Contents/MacOS/install-sloosh" \
        --test-running-application-count "$simulated_install"
  )"
  [[ "$running_count" -gt 0 ]] && break
  sleep 0.05
done
[[ "$running_count" -gt 0 ]] || {
  echo "installer did not recognize the running sandbox Sloosh GUI" >&2
  exit 1
}
env SLOOSH_INSTALLER_TEST_MODE=1 \
  "$mounted_installer/Contents/MacOS/install-sloosh" \
    --test-stop-application "$tmp_dir/not-the-running-app/Sloosh.app"
running_count="$(
  env SLOOSH_INSTALLER_TEST_MODE=1 \
    "$mounted_installer/Contents/MacOS/install-sloosh" \
      --test-running-application-count "$simulated_install"
)"
[[ "$running_count" -gt 0 ]] || {
  echo "installer stopped a Sloosh GUI at the wrong bundle path" >&2
  exit 1
}
env SLOOSH_INSTALLER_TEST_MODE=1 \
  "$mounted_installer/Contents/MacOS/install-sloosh" \
    --test-stop-application "$simulated_install"
for _ in {1..100}; do
  running_count="$(
    env SLOOSH_INSTALLER_TEST_MODE=1 \
      "$mounted_installer/Contents/MacOS/install-sloosh" \
        --test-running-application-count "$simulated_install"
  )"
  [[ "$running_count" -eq 0 ]] && break
  sleep 0.05
done
if [[ "$running_count" -ne 0 ]]; then
  echo "installer did not stop the running sandbox Sloosh GUI" >&2
  exit 1
fi
if [[ -S "$running_gui_home/.sloosh/sloosh.sock" ]]; then
  env SLOOSH_INSTALLER_TEST_MODE=1 \
    "$mounted_installer/Contents/MacOS/install-sloosh" \
      --test-shutdown "$running_gui_home"
fi
test_gui_started=0

# An unrelated existing CLI must never be overwritten.
conflict_home="$tmp_dir/conflict-home"
conflict_applications="$tmp_dir/conflict-Applications"
mkdir -p "$conflict_home/.local/bin"
printf 'keep-existing-cli\n' >"$conflict_home/.local/bin/sloosh"
conflict_output="$(
  env SLOOSH_INSTALLER_TEST_MODE=1 \
    "$mounted_installer/Contents/MacOS/install-sloosh" \
    --test-install "$conflict_applications" "$conflict_home"
)"
grep -F "Existing item at ~/.local/bin/sloosh was left unchanged." \
  <<<"$conflict_output" >/dev/null
test "$(cat "$conflict_home/.local/bin/sloosh")" = "keep-existing-cli"

# An unrelated CLI symlink is also preserved exactly.
link_home="$tmp_dir/link-home"
link_applications="$tmp_dir/link-Applications"
mkdir -p "$link_home/.local/bin"
ln -s "/opt/homebrew/bin/sloosh" "$link_home/.local/bin/sloosh"
link_output="$(
  env SLOOSH_INSTALLER_TEST_MODE=1 \
    "$mounted_installer/Contents/MacOS/install-sloosh" \
    --test-install "$link_applications" "$link_home"
)"
grep -F "Existing CLI link at ~/.local/bin/sloosh was left unchanged." \
  <<<"$link_output" >/dev/null
test "$(readlink "$link_home/.local/bin/sloosh")" = "/opt/homebrew/bin/sloosh"

# A same-named ordinary directory is user data, not an app to replace.
unrecognized_home="$tmp_dir/unrecognized-home"
unrecognized_applications="$tmp_dir/unrecognized-Applications"
mkdir -p "$unrecognized_home" "$unrecognized_applications/Sloosh.app"
printf 'keep-unrecognized-directory\n' > \
  "$unrecognized_applications/Sloosh.app/marker"
if env SLOOSH_INSTALLER_TEST_MODE=1 \
  "$mounted_installer/Contents/MacOS/install-sloosh" \
    --test-install "$unrecognized_applications" "$unrecognized_home"; then
  echo "installer replaced an unrecognized Sloosh.app directory" >&2
  exit 1
fi
test "$(cat "$unrecognized_applications/Sloosh.app/marker")" = \
  "keep-unrecognized-directory"

# Upgrades stop a resident daemon through the pre-handshake Shutdown request;
# they never execute the old installed app.
shutdown_home="$tmp_dir/shutdown-home"
mkdir -p "$shutdown_home"
SLOOSH_HOME="$shutdown_home/.sloosh" \
  "$mounted_app/Contents/Helpers/slooshd" \
  >"$tmp_dir/shutdown-daemon.log" 2>&1 &
test_daemon_pid=$!
for _ in {1..100}; do
  [[ -S "$shutdown_home/.sloosh/sloosh.sock" ]] && break
  sleep 0.05
done
test -S "$shutdown_home/.sloosh/sloosh.sock"
env SLOOSH_INSTALLER_TEST_MODE=1 \
  "$mounted_installer/Contents/MacOS/install-sloosh" \
    --test-shutdown "$shutdown_home"
for _ in {1..100}; do
  [[ -e "$shutdown_home/.sloosh/sloosh.sock" ]] || break
  sleep 0.05
done
[[ ! -e "$shutdown_home/.sloosh/sloosh.sock" ]] || {
  echo "installer did not stop the sandbox daemon" >&2
  exit 1
}
wait "$test_daemon_pid"
test_daemon_pid=""

# Exercise the real copied-helper handoff. The helper waits for the installer
# process to exit, then ejects the volume from outside it.
env SLOOSH_INSTALLER_TEST_MODE=1 \
  "$mounted_installer/Contents/MacOS/install-sloosh" --test-cleanup "$mount_dir"
for _ in {1..100}; do
  if ! mount | grep -F " on $mount_probe_path " >/dev/null; then
    break
  fi
  sleep 0.1
done
if mount | grep -F " on $mount_probe_path " >/dev/null; then
  echo "installer cleanup helper did not eject $mount_dir" >&2
  exit 1
fi
mounted=0

echo "$dmg"
