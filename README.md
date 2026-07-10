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

Building from source requires Rust 1.88 or newer.

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

- Agent-facing commands never receive an SSH password, private key, or vault
  contents. The daemon uses the encrypted vault for SSH authentication; the
  human-only `approve` command temporarily unlocks it in the approving CLI so
  the human can inspect the complete grant before it is sent to the daemon.
- Access is granted per-host via a **lease**, not a blanket unlock —
  requesting one host never authorizes another.
- Bastion paths are first-class: `ProxyJump` chains (multi-hop) and
  vault-level jump hosts are followed automatically. During approval, the CLI
  shows the fully-expanded host list and the daemon independently recomputes
  it; a mismatch fails closed. Each vault-backed hop is re-checked before it
  is dialed.
- Leases are approved out of band, by a human, in a separate terminal —
  the agent cannot approve its own request.
- A lease is bound to the requesting process's ancestry (PID + start
  time), so subagents spawned under an authorized agent inherit access
  automatically, with zero extra configuration.
- Pending requests expire after 15 minutes and are dropped after five wrong
  master-password attempts. Active leases expire after two idle hours or an
  absolute eight hours, whichever comes first.
- Lease expiry revokes access but does not kill an underlying shell session;
  re-approval can attach to that session again. Port forwards are different:
  they are live network access and are closed when their lease ends.
- Vault mutations are serialized and replace the encrypted file atomically.
  The sloosh state directory is mode `0700`; sockets, vault, logs, and spool
  files are kept private with mode `0600` where applicable.

## How it works

`sloosh` is a single binary that runs as both the CLI you invoke and a
long-lived background daemon (`sloosh daemon run`), auto-started on first
use. The CLI and daemon communicate through a Unix domain socket inside a
private directory. The daemon obtains the caller PID from kernel peer
credentials; the CLI checks that the daemon peer has the same effective UID
and resolves to the current sloosh executable. It then requires wire protocol
version 2 before sending normal requests. The client checks `Status`, sends a
versioned `Hello`, and waits for `ProtocolReady`; the daemon rejects ordinary
requests until that handshake succeeds, before request side effects begin.

Protocol 2 uses bounded newline-delimited JSON for control messages and
switches to bounded, length-prefixed raw frames for SFTP bytes. These checks
protect against another OS user and an obvious wrong-daemon socket. They do
not defend against hostile code already running as the same UID, and the
executable-path check is not code signing.

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
time-limited lease. Approval displays the final `ProxyJump`-expanded host
list before activation. First-use host-key confirmation follows the configured
`ProxyJump` route and prompts in dependency order, so each bastion is trusted
before it is used to reach a later target.

### File transfer and output limits

`put` and `get` open an SFTP channel on the session's existing authenticated
SSH connection. The CLI, not the daemon, owns local filesystem access. File
bytes cross the local socket in raw frames of at most 1 MiB, but a transfer
may contain any number of frames: there is no total file-size limit.

The daemon authorizes a transfer once during setup, before `TransferReady`, and
does not re-check the lease per frame. After `TransferReady`, a finite transfer
is allowed to finish even if its lease later reaches the two-hour idle or
eight-hour absolute expiry; expiry still blocks every new operation. This
prevents lease duration from becoming an implicit NAS file-size limit.
Sloosh replaces `russh-sftp`'s default 10-second per-request timeout with
Tokio's far-future deadline (roughly 30 years in the pinned release). This is
operationally unbounded for NAS reads, writes, opens, and closes, while SSH,
server, filesystem, and network failures still end the transfer.

- `put` creates or truncates the remote destination before streaming. It is
  not an atomic remote replacement; a failed transfer can leave a partial
  remote file.
- `get` writes a mode-`0600` temporary file beside the destination and commits
  it only after the full transfer succeeds. It refuses to replace an existing
  local file unless `--force` is given.
- A command reply returns at most about 30,000 characters. Raw command output
  is retained in a spool file up to 64 MiB per run, with a 64 MiB retention
  budget per session directory and a 1 GiB global budget shared by active-run
  reservations and retained files; a marker records when per-run persistence
  hits its limit, and older retained files are removed first. These spool
  limits apply only to command output, not SFTP transfers.

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
| `put` | Stream a local file to a remote path over SFTP; the remote destination is truncated first. |
| `get` | Stream a remote file to an atomic local download; refuses to overwrite unless `--force` is used. |
| `forward` | Open a lease-gated, loopback-only `-L` forward; `-R` is currently disabled. `forward ls` and `forward stop` manage live forwards. |
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

## Development

```
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo +1.88.0 check --all-targets --locked
```

All four gates must pass cleanly. CI runs formatting and clippy on stable
Rust, non-live tests on Linux and macOS, an explicit Rust 1.88 MSRV check,
and live session/SFTP/forward tests against a local Linux sshd.

Most of the test suite runs without any external dependency. The
live integration tests are gated behind environment variables:

```
SLOOSH_TEST_SSH_HOST=myhost cargo test --test ssh_session -- --test-threads=1
SLOOSH_TEST_SSH_HOST=myhost cargo test --test sftp_transfer -- --test-threads=1
SLOOSH_TEST_SSH_HOST=myhost cargo test --test forward -- --test-threads=1
SLOOSH_TEST_SSH_HOST=user@host SLOOSH_TEST_SSH_PASSWORD=... \
  cargo test --test proxy_jump -- --test-threads=1
```

`myhost` can be an alias resolvable via `~/.ssh/config` or a literal
`user@host`/`host`. Single-threaded is required — each test points
`$SLOOSH_HOME` at its own temp directory, and that isolation (which keeps
the run from ever touching your real `~/.sloosh/vault`) only holds with one
test running at a time. Hosted CI runs the first three live suites. The
password-authenticated `proxy_jump` suite remains manual because enabling
password authentication on a shared runner's system sshd would be too broad.

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the full contribution flow,
including which areas of the codebase get extra review scrutiny.

## Platform support

macOS and Linux today. Windows support (a Named Pipe transport in place of
Unix domain sockets, plus a PID-reuse-aware process-ancestry check) is
planned — see Roadmap below.

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
