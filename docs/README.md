# Documentation

Each topic has one owner. Other documents link to it instead of copying its
details.

## Users

- [`../README.md`](../README.md): product overview, quickstart, and commands.
- [`getting-started/installation.md`](getting-started/installation.md): binary
  downloads, checksums, upgrades, and source installation.
- [`../SECURITY.md`](../SECURITY.md): threat model, guarantees, and known
  limits.

## Implementation

- [`internals/architecture.md`](internals/architecture.md): component
  boundaries, data ownership, and runtime behavior.
- [`internals/protocol.md`](internals/protocol.md): exact CLI-daemon wire
  protocol and framing.
- [`internals/design.md`](internals/design.md): Chinese design intent and
  implementation status. It points to the owner documents for exact details.

## Maintainers

- [`../CONTRIBUTING.md`](../CONTRIBUTING.md): development, tests, and review
  expectations.
- [`maintainers/releasing.md`](maintainers/releasing.md): versioning, crates.io,
  and GitHub Release procedure.
- [Agent guide](https://github.com/ReiSuzunami/sloosh/blob/main/AGENTS.md):
  repository instructions for coding agents.

The operational agent skill lives in [`../skills/sloosh/`](../skills/sloosh/).
It teaches agents how to use sloosh; it does not replace user or maintainer
documentation.
