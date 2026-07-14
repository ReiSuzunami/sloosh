# Releasing

Sloosh has two independent distribution channels:

| Channel | Audience | Artifact |
|---|---|---|
| GitHub Releases | ordinary users | prebuilt macOS and Linux binaries |
| crates.io | Rust users | source package compiled by `cargo install` |

GitHub Releases are the primary channel. A crates.io publish does not provide a
prebuilt binary and is not required for GitHub release creation.

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
version=0.1.0
git tag -a "v$version" -m "sloosh v$version"
git push origin "v$version"
```

`.github/workflows/release.yml` builds and tests these release targets:

- `aarch64-apple-darwin` on an Apple silicon runner;
- `x86_64-apple-darwin` on an Intel runner;
- `x86_64-unknown-linux-musl` on an x86_64 Linux runner.

It combines the two native macOS slices into one ad-hoc-signed universal
binary, packages both platforms, generates `SHA256SUMS`, records GitHub build
provenance attestations for a public repository, and creates the GitHub
Release. No publishing secret is required; GitHub's scoped workflow token
creates the release.

After the workflow succeeds:

```sh
gh release download "v$version" --dir /tmp/sloosh-release
cd /tmp/sloosh-release
sha256sum -c SHA256SUMS
```

For a public repository, also verify both archives with
`gh attestation verify <archive> --repo ReiSuzunami/sloosh`. Private repository
attestation availability depends on the GitHub plan, so the workflow does not
make private releases depend on it.

Extract both archives and run `sloosh --version`. On macOS, also verify
`lipo -archs` reports `x86_64 arm64`. Do not describe the macOS artifact as
notarized until Developer ID signing and Apple notarization are configured.

## crates.io

The `sloosh` crate name was unallocated when this procedure was written, but
names are first-come, first-served. The first publish requires a crates.io
account and API token:

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
```

If only the GitHub Release exists, ordinary users still have the supported
no-build installation path. If only crates.io exists, users must compile.
