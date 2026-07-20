# Documentation

Documentation is bilingual where users benefit most. English remains canonical
for exact security, architecture, protocol, and maintainer contracts. Chinese
user guides are maintained translations, not separate specifications.

| Topic | English | 简体中文 | Authority |
|---|---|---|---|
| Product and install/build entry | [`README.md`](../README.md) | [`README.zh-CN.md`](../README.zh-CN.md) | User entry |
| Installation and upgrades | [`installation.md`](getting-started/installation.md) | [`installation.zh-CN.md`](getting-started/installation.zh-CN.md) | Distribution and platform requirements |
| Security model | [`SECURITY.md`](../SECURITY.md) | — | Threat model, guarantees, and known limits |
| Architecture | [`architecture.md`](internals/architecture.md) | — | Component boundaries, ownership, and runtime behavior |
| Wire protocol | [`protocol.md`](internals/protocol.md) | — | Exact CLI-daemon messages, framing, and sequencing |
| Contributing and tests | [`CONTRIBUTING.md`](../CONTRIBUTING.md) | — | Development and verification workflow |
| Releasing | [`releasing.md`](maintainers/releasing.md) | — | Versioning, crates.io, and GitHub Releases |

Non-canonical research notes:

- [`native-approval-research.md`](internals/native-approval-research.md)
  records macOS/Windows biometric-approval feasibility and unpaid distribution
  options. `SECURITY.md` and `architecture.md` remain authoritative for shipped
  behavior.

Repository instructions for coding agents live in
[`AGENTS.md`](https://github.com/ReiSuzunami/sloosh/blob/main/AGENTS.md). The
operational [`skills/sloosh/`](../skills/sloosh/) artifact teaches agents how
to use sloosh; it does not define project internals.

When behavior changes, update the canonical owner first and every affected
translation in the same commit. Do not copy exact security or protocol limits
into user guides.
