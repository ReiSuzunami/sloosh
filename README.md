# sloosh

English | [简体中文](./README.zh-CN.md)

[![CI](https://github.com/ReiSuzunami/sloosh/actions/workflows/ci.yml/badge.svg)](https://github.com/ReiSuzunami/sloosh/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust edition 2024](https://img.shields.io/badge/rust-edition%202024-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)

`sloosh` is an SSH operations tool built for coding agents. It fixes two
pain points that plain `ssh`/subprocess calls have when an agent drives
them: **state doesn't persist** — every shell call starts fresh, losing
`cwd`, environment variables, and background jobs — and **credentials
aren't isolated** — the agent typically needs the password or key inline
to connect at all. `sloosh` keeps a long-lived remote shell per host behind
a background daemon, and gates all host access behind a human-approved,
out-of-band lease so the agent never sees a credential.

## Install

Download a prebuilt archive from the
[latest GitHub Release](https://github.com/ReiSuzunami/sloosh/releases/latest):

- `sloosh-macos-universal.tar.gz` for Apple silicon and Intel Macs.
- `sloosh-linux-x86_64-musl.tar.gz` for 64-bit x86 Linux.

Extract the archive, then install the binary somewhere on `PATH`:

```sh
install -d "$HOME/.local/bin"
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
sloosh --version
```

No Rust toolchain is needed. See the
[installation guide](./docs/getting-started/installation.md) for checksum
verification, platform notes, and source installation through crates.io.
The crates.io command becomes available after the first crate publish.

## 60-second quickstart

**Human steps** (one-time setup, run in your own terminal):

```
sloosh vault init                              # set a master password for the credential vault
sloosh add myhost --hostname 1.2.3.4 --user deploy   # enroll a host under an alias
# ... an agent now runs `sloosh request myhost`, prints an approval command ...
sloosh approve <request-id>                    # paste it here, enter the master password
```

**Agent steps:**

```
sloosh request myhost                          # ask for access; show the printed command to your human, then stop and wait
sloosh run myhost "npm test"                   # once approved, run commands in a persistent shell
```

See `sloosh <command> --help` for the full flag reference on any subcommand.

## Core model

`sloosh` is one binary with a short-lived CLI and an auto-started daemon. The
daemon keeps SSH sessions alive; the CLI handles human prompts and local SFTP
paths. Host access requires a time-limited, human-approved lease. Credentials
stay in the encrypted vault and are never returned to an agent-facing command.

This reduces credential exposure and accidental host access, but it is not a
sandbox against hostile code already running as the same OS user. Read
[`SECURITY.md`](./SECURITY.md) before relying on the boundary.

## Commands

One line per subcommand — see `sloosh <command> --help` for the full flag
reference on any of them.

| Command | Description |
|---|---|
| `init` | Install the Agent Skill and initialize the vault in a human terminal. |
| `skill` | Install or inspect the embedded Agent Skill without starting the daemon. |
| `run` | Run a command in a host's default (or named) session, blocking until it finishes or times out. |
| `peek` | Fetch output a session has produced since the last peek. |
| `send` | Send raw keystrokes to a session's PTY (e.g. to answer an interactive prompt). |
| `interrupt` | Send Ctrl-C to a session. |
| `open` | Explicitly open a new named parallel session on a host. |
| `ls` | List known sessions and their state. |
| `kill` | Kill a session (terminates the remote shell). |
| `request` | Request an access lease for one or more hosts (agent side of authorization). |
| `approve` | Approve a pending lease request (human side, run in another terminal). |
| `add` | Add a credential to the vault. Interactive and human-only: there is no flag to pass a secret. |
| `rm` | Remove a credential from the vault. |
| `vault` | Manage the credential vault itself (e.g. first-time initialization). |
| `put` | Stream a local file to a remote path over SFTP; the remote destination is truncated first. |
| `get` | Stream a remote file to an atomic local download; refuses to overwrite unless `--force` is used. |
| `forward` | Open a lease-gated loopback `-L` or remote `-R` forward. `forward ls` and `forward stop` manage live forwards. |
| `status` | Show daemon/session/lease status — the anchor command when unsure what's going on. |
| `daemon` | Manage the sloosh daemon process directly (normally auto-started on demand). |
| `log` | Show the audit log. |

## Using with coding agents

`skills/sloosh/` is a ready-made [Agent Skill](https://agentskills.io)
that teaches an agent `sloosh`'s mental model (sessions are persistent
shells; every host needs a human-approved lease; run `sloosh status` when
lost) without duplicating the `--help` flag reference. The same skill
works in every agent that speaks the SKILL.md standard — install it
whichever way fits your setup:

**Claude Code** — via the [nerv](https://github.com/ReiSuzunami/nerv)
plugin marketplace:

```
/plugin marketplace add ReiSuzunami/nerv
/plugin install sloosh@nerv
```

**Codex** — same marketplace, via the Codex CLI:

```
codex plugin marketplace add ReiSuzunami/nerv
codex plugin add sloosh@nerv
```

**Any agent, via the [skills CLI](https://github.com/vercel-labs/skills)**
(Claude Code, Codex, Cursor, and ~70 others):

```
npx skills add ReiSuzunami/sloosh
```

**Manually** — copy the skill directory into your agent's skills folder:

```
cp -r skills/sloosh ~/.claude/skills/sloosh   # Claude Code
cp -r skills/sloosh ~/.agents/skills/sloosh   # Codex (and other .agents/skills readers)
```

The Skill-first path checks for `sloosh`, explains the official install, and
asks before proposing any binary installation. If the binary is installed
first, run the combined setup yourself in a human terminal:

```sh
sloosh init
```

`sloosh init` installs/verifies the Skill embedded in the binary, then creates
the vault. It auto-detects Codex and Claude Code; use
`sloosh skill status` to inspect the result. The binary never invokes `npx` or
an agent marketplace itself.

## Documentation

- [Documentation map](./docs/README.md)
- [Installation](./docs/getting-started/installation.md)
- [Security model](./SECURITY.md)
- [Architecture](./docs/internals/architecture.md)
- [Wire protocol](./docs/internals/protocol.md)
- [Contributing and tests](./CONTRIBUTING.md)

## Platform support

Sloosh supports macOS and Linux. Prebuilt releases cover macOS on Apple silicon
and Intel, plus 64-bit x86 Linux via a musl-linked binary. Linux requires a
readable procfs for peer executable and process-ancestry checks. Other Linux
CPU architectures currently require a source build. Windows support (a Named
Pipe transport plus PID-reuse-aware process ancestry) is planned.

## Roadmap

Phase 2, roughly in order:

- Windows support (Named Pipe transport).
- `--resilient` sessions anchored to a remote `tmux`, so a dropped SSH
  connection doesn't kill the session.
- Touch ID / Windows Hello-gated approvals, so re-approving doesn't mean
  re-typing the master password (the vault's own encryption stays
  self-contained — no OS keychain involved).
- Verified compatibility with 1Password/Bitwarden `ssh-agent`
  implementations (the ssh_config `IdentityAgent` directive is already
  honored).

## License

Licensed under either of

- [MIT license](./LICENSE-MIT)
- [Apache License, Version 2.0](./LICENSE-APACHE)

at your option, per the usual Rust convention. Unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in this
project shall be dual-licensed as above, without any additional terms or
conditions.
