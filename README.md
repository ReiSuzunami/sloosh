# sloosh

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

```
cargo build --release
# binary at target/release/sloosh — put it on your PATH
```

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

## Security model

- The daemon holds SSH credentials (in an encrypted vault); the agent
  process never sees a password, key, or vault content — only host
  aliases.
- Access is granted per-host via a **lease**, not a blanket unlock —
  requesting one host never authorizes another.
- Leases are approved out of band, by a human, in a separate terminal —
  the agent cannot approve its own request.
- A lease is bound to the requesting process's ancestry (PID + start
  time), so subagents spawned under an authorized agent inherit access
  automatically, with zero extra configuration.
- Leases expire on idle timeout; expiry revokes host access but never
  kills the underlying shell session, which reconnects cleanly once
  access is re-approved.

## How it works

`sloosh` is a single binary that runs as both the CLI you invoke and a
long-lived background daemon (`sloosh daemon run`), auto-started on first
use. The CLI and daemon talk over a Unix domain socket (mode `0600`,
same-user only) using a newline-delimited JSON protocol, so the exchange
stays debuggable with plain tools like `nc -U`.

The daemon keeps one persistent PTY shell per host session alive on the
remote end — `cd`, exported environment variables, and background jobs
all survive across separate `sloosh run` calls, because each call talks
to the same living shell rather than opening a fresh subprocess. Command
output is framed with a generated sentinel marker so the daemon can tell
exactly where a command's output ends and what its exit code was, even
though everything arrives as one raw PTY byte stream; a scrubber strips
those markers (and ANSI noise) before anything reaches you.

Access to a host is never implicit. An agent calls `sloosh request <host>`,
which prints an approval command; a human runs that command in a
*separate* terminal and enters the vault's master password to grant a
time-limited lease. The daemon uses kernel-level peer credentials
(`SO_PEERCRED`/`LOCAL_PEERPID`) to identify the calling process's ancestry
and binds the lease to it, so subagents spawned by an already-authorized
agent inherit access automatically — with zero extra configuration — while
credentials themselves never leave the vault or cross into agent-visible
output.

For the full design (wire protocol, session/output model, audit log, vault
crypto), see [`DESIGN.md`](./DESIGN.md) (the authoritative design document,
in Chinese) or [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) (an English
overview).

## Commands

One line per subcommand — see `sloosh <command> --help` for the full flag
reference on any of them.

| Command | Description |
|---|---|
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
| `put` | Upload a local file to a host over SFTP. |
| `get` | Download a remote file from a host over SFTP. |
| `status` | Show daemon/session/lease status — the anchor command when unsure what's going on. |
| `daemon` | Manage the sloosh daemon process directly (normally auto-started on demand). |
| `log` | Show the audit log. |

## Using with Claude Code

`skill/` contains a ready-made [Claude Code Skill](https://docs.claude.com/en/docs/claude-code/skills)
that teaches an agent `sloosh`'s mental model (sessions are persistent
shells; every host needs a human-approved lease; run `sloosh status` when
lost) without duplicating the `--help` flag reference. Install it by
copying the directory into your skills folder:

```
cp -r skill ~/.claude/skills/sloosh
```

## Development

```
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

All three gates (tests, clippy, fmt) must pass cleanly; they're what CI
runs on every PR.

Most of the test suite runs without any external dependency. The
integration tests in `tests/ssh_session.rs` exercise a real SSH session
end-to-end and are gated behind an environment variable so they don't run
(or hang) in CI/sandboxes by default:

```
SLOOSH_TEST_SSH_HOST=myhost cargo test --test ssh_session -- --test-threads=1
```

`myhost` can be an alias resolvable via `~/.ssh/config` or a literal
`user@host`/`host`. Single-threaded is required — each test points
`$SLOOSH_HOME` at its own temp directory, and that isolation (which keeps
the run from ever touching your real `~/.sloosh/vault`) only holds with one
test running at a time. See the module doc comment in
[`tests/ssh_session.rs`](./tests/ssh_session.rs) for details.

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the full contribution flow,
including which areas of the codebase get extra review scrutiny.

## Platform support

macOS and Linux today. Windows support (a Named Pipe transport in place of
Unix domain sockets, plus a PID-reuse-aware process-ancestry check) is
planned — see Roadmap below.

## Roadmap

Phase 2, roughly in order:

- `forward` — SSH port forwarding.
- Windows support (Named Pipe transport).
- `--resilient` sessions anchored to a remote `tmux`, so a dropped SSH
  connection doesn't kill the session.
- OS keychain / Touch ID / Windows Hello-gated vault unlock, as an
  alternative to the master password.
- Verified compatibility with 1Password/Bitwarden `ssh-agent`
  implementations.

## License

Licensed under either of

- [MIT license](./LICENSE-MIT)
- [Apache License, Version 2.0](./LICENSE-APACHE)

at your option, per the usual Rust convention. Unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in this
project shall be dual-licensed as above, without any additional terms or
conditions.
