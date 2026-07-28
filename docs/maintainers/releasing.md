# Releasing

Sloosh has three independent distribution channels:

| Channel | Audience | Artifact |
|---|---|---|
| GitHub Releases | ordinary users | prebuilt command-line archives, macOS DMG, and Windows desktop ZIP |
| Homebrew tap | macOS and Linux users | prebuilt `sloosh` + `slooshd` |
| crates.io | Rust users | command-line source package compiled by `cargo install` |

GitHub Releases are the primary channel. A crates.io publish does not provide a
prebuilt binary and is not required for GitHub release creation. Homebrew and
crates.io do not distribute or build the desktop app or DMG; those remain
GitHub Release artifacts.

## Before tagging

1. Update `version` in `Cargo.toml`; run `cargo check --locked` so `Cargo.lock`
   records the same package version.
2. Update user-visible behavior and platform support in the owning documents.
3. Run every command in the required gate from `CONTRIBUTING.md`.
4. Run `cargo publish --dry-run --locked` and inspect `cargo package --list`.
5. Merge the release commit to `main` and wait for CI to pass.
6. Confirm repository visibility. Release assets require repository read
   access; make the repository public before advertising downloads to ordinary
   users.

The release workflow repeats the gates against the exact tag commit. It also
requires the tag version to equal `Cargo.toml` and the tagged commit to be in
`origin/main`.

## GitHub Release

Create and push an annotated `v<version>` tag:

```sh
version=0.2.2
git tag -a "v$version" -m "sloosh v$version"
git push origin "v$version"
```

`.github/workflows/release.yml` builds and tests these release targets:

- `aarch64-apple-darwin` on an Apple silicon runner;
- `x86_64-apple-darwin` on an Intel runner;
- `x86_64-unknown-linux-musl` on an x86_64 Linux runner.
- `x86_64-pc-windows-msvc` on a Windows runner.

It combines `sloosh`, `slooshd`, and Tauri desktop slices into three universal
binaries. The command-line archive contains the first two. The DMG contains
only the desktop and private `slooshd`, then ad-hoc signs both, the payload app,
and native installer. The Windows ZIP contains CLI, daemon, desktop, and the
Windows Hello helper as four sibling executables. It packages Linux, generates `SHA256SUMS`, records GitHub
build provenance attestations for a public repository, and creates the GitHub
Release. No publishing secret is required; GitHub's scoped workflow token
creates the release.

After the workflow succeeds:

```sh
gh release download "v$version" --dir /tmp/sloosh-release
cd /tmp/sloosh-release
sha256sum -c SHA256SUMS
```

For a public repository, also verify every archive and the DMG with
`gh attestation verify <asset> --repo ReiSuzunami/sloosh`. Private repository
attestation availability depends on the GitHub plan, so the workflow does not
make private releases depend on it.

Extract each archive and run `sloosh --version` and `slooshd --version`. On
macOS, also verify the DMG and its app bundle:

On Windows, extract the ZIP, verify all four executables are siblings, run the
two version commands, open `Sloosh.exe`, and manually test one enrollment,
cancellation, and successful Windows Hello approval. Never automate or bypass
the Hello prompt.

```sh
dmg="Sloosh-$version-macos-universal.dmg"
hdiutil verify "$dmg"
mount_dir="$(mktemp -d)"
hdiutil attach -nobrowse -readonly -mountpoint "$mount_dir" "$dmg"
installer="$mount_dir/Install Sloosh.app"
payload="$installer/Contents/Helpers/Sloosh.app"
codesign --verify --deep --strict "$installer"
codesign --verify --deep --strict "$payload"
test -s "$mount_dir/.DS_Store"
test -s "$mount_dir/.background/background.png"
lipo -archs "$installer/Contents/MacOS/install-sloosh"
lipo -archs "$payload/Contents/MacOS/Sloosh"
lipo -archs "$payload/Contents/Helpers/slooshd"
"$payload/Contents/Helpers/slooshd" --version
test ! -e "$payload/Contents/Helpers/sloosh"
hdiutil detach "$mount_dir"
rmdir "$mount_dir"
```

Both architecture checks must report `x86_64 arm64` in either order. Opening
the DMG must show one large, centered `Install Sloosh` app. The package script
also installs the payload twice in a temporary sandbox, verifies that a fresh
install stops an existing sibling daemon, forces a staged replacement failure
to verify rollback, verifies the CLI link removal and conflict-preservation
behavior, and exercises the cleanup helper's volume ejection handoff. The
payload must contain an independent GUI executable and private daemon, no
public CLI, and no newly created CLI link. Do not describe the macOS artifact
as notarized until Developer ID signing and Apple notarization are configured.

## Homebrew tap

After the GitHub assets are final, update the tap formula URLs and SHA-256
values for both platform archives. The formula must install both binaries:

```ruby
def install
  bin.install "sloosh", "slooshd"
end

test do
  assert_equal "sloosh #{version}", shell_output("#{bin}/sloosh --version").strip
  assert_equal "slooshd #{version}", shell_output("#{bin}/slooshd --version").strip
end
```

Run `brew style`, `brew audit --strict`, and `brew test` against the updated
formula on every supported platform before pushing the tap change. Do not point
the formula at the DMG: Homebrew provides the command-line package, not the
desktop app.

## crates.io

Publishing requires a crates.io account and an authenticated or trusted
publishing identity:

```sh
cargo login
cargo publish --locked
```

Published versions cannot be overwritten. Confirm the package contents,
version, repository state, and GitHub assets before running the command. After
the first publish, configure crates.io Trusted Publishing before automating
this step; do not store a long-lived crates.io token in the repository.

Verify the source-install channel in a clean directory:

```sh
cargo install sloosh --version "$version" --locked
sloosh --version
slooshd --version
```

If only the GitHub Release exists, ordinary users still have the supported
no-build installation path. If only crates.io exists, users must compile.
