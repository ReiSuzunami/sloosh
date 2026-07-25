# Documentation

Documentation is bilingual where users benefit most. `README.md` is the
simplified Chinese primary entry; `README.en.md` is its maintained English
translation. English remains canonical for exact security, architecture,
protocol, and maintainer contracts. Root entry points intentionally use
unsuffixed `README.md` for simplified Chinese; under `docs/`, unsuffixed files
are English and `.zh-CN.md` files are their simplified Chinese translations.

| Topic | 简体中文 | English | Authority |
|---|---|---|---|
| Product and install/build entry | [`README.md`](../README.md) | [`README.en.md`](../README.en.md) | User entry |
| Human usage manual | [`manual.zh-CN.md`](manual.zh-CN.md) | [`manual.md`](manual.md) | Human setup and everyday CLI/desktop use |
| Installation and upgrades | [`installation.zh-CN.md`](getting-started/installation.zh-CN.md) | [`installation.md`](getting-started/installation.md) | Distribution and platform requirements |
| Agent operations | — | [`SKILL.md`](../skills/sloosh/SKILL.md) | Safe Agent setup and remote-operation workflow |
| Security model | — | [`SECURITY.md`](../SECURITY.md) | Threat model, guarantees, and known limits |
| Architecture | — | [`architecture.md`](internals/architecture.md) | Component boundaries, ownership, and runtime behavior |
| Wire protocol | — | [`protocol.md`](internals/protocol.md) | Exact CLI-daemon messages, framing, and sequencing |
| Contributing and tests | — | [`CONTRIBUTING.md`](../CONTRIBUTING.md) | Development and verification workflow |
| Support | — | [`SUPPORT.md`](../SUPPORT.md) | User support scope and safe diagnostics |
| Community conduct | — | [`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) | Participation and enforcement expectations |
| Releasing | — | [`releasing.md`](maintainers/releasing.md) | Versioning, crates.io, and GitHub Releases |

Repository-only, non-canonical research notes:

- [`native-approval-research.md`](https://github.com/ReiSuzunami/sloosh/blob/main/docs/research/native-approval-research.md)
  records macOS/Windows biometric-approval feasibility and unpaid distribution
  options.
- [`cloud-mcp-ssh-research.md`](https://github.com/ReiSuzunami/sloosh/blob/main/docs/research/cloud-mcp-ssh-research.md)
  compares hosted MCP/SSH execution models.

Research records dated external facts and design exploration; it is not shipped
in release archives or the crates.io package. `SECURITY.md`, `architecture.md`,
and `protocol.md` remain authoritative for shipped behavior.

Repository instructions for coding agents live in
[`AGENTS.md`](https://github.com/ReiSuzunami/sloosh/blob/main/AGENTS.md). The
operational Agent Skill teaches agents how to use sloosh; it does not define
project internals.

When behavior changes, update the canonical owner first and every affected
translation in the same commit. Do not copy exact security or protocol limits
into user guides.
