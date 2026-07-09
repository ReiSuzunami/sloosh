# Architecture

This is an English overview of `sloosh`'s design. The authoritative,
more detailed design document is [`DESIGN.md`](../DESIGN.md) (written in
Chinese); section references below (`§N`) point back to it. This document
favors accuracy over completeness — where something isn't implemented yet,
it says so.

## 1. Components

```
Coding Agent --spawn--> sloosh (CLI) ---- UDS, NDJSON protocol ----+
                                                                    v
Human (separate   --approve-->  sloosh          ------------> sloosh daemon
 terminal)                      approve/add                    - SSH connection pool (russh)
                                                                 - persistent PTY sessions
                                                                 - vault (master-password encrypted)
                                                                 - lease manager
                                                                 - audit log
```

(DESIGN.md §1)

- **CLI** (`src/cli/`) — entry point for both the agent and the human.
  Parses arguments with `clap` (`src/cli/args.rs` is the source of truth
  for the full subcommand surface — see the README's command table), talks
  to the daemon over the local transport, and auto-spawns the daemon on
  first use if its socket isn't reachable.
- **Daemon** (`src/daemon/mod.rs`) — a plain subcommand of the same binary
  (`sloosh daemon run`), not a separate crate, so distribution stays a
  single binary and the CLI can bootstrap it transparently. It owns the
  Unix domain socket, runs the accept loop, and routes every request
  (`Status`/`Shutdown`, session management, vault/lease authorization) to
  the relevant module.
- **Why a persistent daemon, not a stdio MCP-style server**: a daemon that
  outlives any single agent process means an agent crash/restart doesn't
  lose SSH session state, and multiple agent processes can share the same
  underlying connections — a server tied to one agent process's stdio
  offers neither (DESIGN.md §1).

## 2. Transport: UDS with kernel peer credentials

`src/transport/` defines a `Channel` trait abstracting local IPC so
platform-specific bits never leak into caller code. The only implementation
today is `src/transport/unix.rs` (Unix domain sockets, macOS + Linux); a
Windows Named Pipe implementation is planned for phase 2 (DESIGN.md §2,
§8) but does not exist yet.

The authorization model (§4) depends on knowing, with kernel-level
certainty, which OS process is on the other end of a connection — not a
PID the caller merely *claims*. That's why the transport is a Unix domain
socket rather than TCP loopback: UDS exposes peer credentials via
`SO_PEERCRED` (Linux) or `LOCAL_PEERPID` (macOS), and every `Channel`
implementation must provide `peer_pid()`. TCP `localhost` has no
equivalent trusted mechanism (DESIGN.md §2).

The socket path is `$XDG_RUNTIME_DIR/sloosh.sock` on Linux and
`~/.sloosh/sloosh.sock` on macOS, mode `0600` (same-user only) — the outer
perimeter of the trust model; see §4 for what's layered on top of it.

Messages are newline-delimited JSON (NDJSON), one object per line,
internally tagged by a `"type"` field (`src/proto.rs`) — chosen over a
binary/schema-compiled protocol because performance isn't a constraint
here, and NDJSON stays debuggable with plain tools like `nc -U`. Secrets
that legitimately cross the socket (e.g. a master password typed during
`approve`) are wrapped in `SecretString`, whose `Debug` impl always prints
a redacted placeholder, so they can't leak into the trace-level
`debug!(?req, ...)` logging every inbound message goes through.

## 3. Session model: persistent PTY, sentinel framing, spool

The core value proposition: each session keeps a long-lived PTY shell open
on the remote host (`src/daemon/session.rs`), so `cwd`, environment
variables, venv activation, and background jobs survive across separate
`sloosh run` calls — something a fresh `ssh host cmd` subprocess per call
cannot offer (DESIGN.md §3).

- **Implicit addressing.** `sloosh run <host> "cmd"` creates or reuses that
  host's default session; `--session <name>` (or `sloosh open <host>
  <name>`) opens a second, parallel shell on the same host.
- **Sentinel-based framing.** Each command is followed by a generated
  marker line shaped `__sloosh_<32 lowercase hex>__` (`SENTINEL_PREFIX`/
  `SENTINEL_HEX_LEN`/`SENTINEL_SUFFIX` in `session.rs`), printed via
  `printf` so the daemon can locate a command's exit code and output
  boundary within one raw PTY byte stream.
- **`FrameScrubber`** sits between the raw PTY stream and the ring
  buffer/spool: it strips sentinel lines by shape (not by matching a list
  of currently-armed sentinels, so a stale sentinel can't leak through),
  guaranteeing no `__sloosh_*__` line ever reaches agent-visible output.
  It also holds back any byte sequence that might be a not-yet-complete
  marker, so a marker split across reads can't leak half of itself.
- **Execution modes:** `run` blocks by default until the sentinel resolves
  or a timeout elapses — hitting the timeout does *not* kill the command,
  it returns `running` plus output-so-far; `peek` is cursor-based, by
  default returning only output since the caller's last peek (mirroring
  Claude Code's `BashOutput`, to avoid re-sending/re-billing tokens for
  output already seen), with `--tail N` for an explicit re-read; `send`
  writes raw keystrokes (for interactive prompts); `interrupt` sends
  Ctrl-C. Every `run`/`peek` reply carries an explicit status: `done`,
  `running`, or `dead`.
- **Disconnection semantics: report death, don't silently resurrect.** If
  the SSH connection drops, the daemon reports the session `dead` with the
  reason and last output, rather than silently opening a fresh shell in a
  `cwd` the agent doesn't expect. A remote-tmux-anchored `--resilient` mode
  is planned; the `dead`/`running`/`done` vocabulary already reserves room
  for it (DESIGN.md §3).
- **Session lifecycle is independent of lease lifecycle.** A lease
  expiring doesn't kill the session or its processes; it reattaches
  cleanly once re-approved. Sessions are reaped independently on their own
  idle timeout (8h of no activity).

### Output handling (DESIGN.md §5)

- The shell is initialized with `NO_COLOR=1 TERM=dumb`; the daemon also
  strips ANSI by default (`--raw` opts back into unprocessed output).
- A reply's `output` field is capped (`MAX_OUTPUT_CHARS` = 30,000 chars,
  sized similarly to Claude Code's `BASH_MAX_OUTPUT_LENGTH`), truncated
  from the front with a marker and total byte count.
- The **full, untruncated** output is always spooled to disk
  (`~/.sloosh/spool/<host>--<session>/<seq>.log`; the reply includes the
  path) so
  the agent can `grep`/`tail` large output locally without it crossing the
  socket or entering context. Capped at `MAX_SPOOL_DIR_BYTES` (64 MiB) per
  session, oldest files deleted first.
- A 256 KiB in-memory ring buffer per session (`RING_CAPACITY`) backs
  `peek`'s cursor reads.
- `put`/`get` reuse the session's existing SSH connection over SFTP
  (`russh-sftp`); file bytes never cross the local UDS socket — the CLI
  sends only the path, and the daemon (same OS user) reads/writes the file
  directly.

## 4. Authorization model

The project's core design contribution: an agent can drive a real SSH
session without ever holding, seeing, or exfiltrating a credential
(DESIGN.md §4).

**Vault** (`src/daemon/vault.rs`) stores credentials at `~/.sloosh/vault`
as a versioned JSON envelope: Argon2id KDF parameters + nonce + AEAD
ciphertext, sealing a map from host alias to `HostEntry`. The master
password is run through Argon2id to derive a 32-byte ChaCha20-Poly1305
key; there's no separate verifier — successful AEAD decryption *is* the
password check, and every save writes a fresh nonce. Credential enrollment
(`sloosh add`) is human-only and interactive: no flag or code path accepts
a plaintext secret as an argument, since that would put the credential
through the agent's own context/argv. While at least one lease is active,
the derived key is cached in memory so SSH auth doesn't re-prompt on every
call; the cache clears the moment the last lease expires. Passwords are
`zeroize`d once unneeded, and never appear in logs, errors, or `Debug`
output (`SecretString` in `src/proto.rs` enforces this on the wire).
Planned, without changing the on-disk format: OS-keychain- or
biometric-gated (Touch ID / Windows Hello) key-wrapping as an alternative
unlock path. A `HostEntry` may also carry an optional `jump` field — a jump
host alias, resolvable via the vault or `~/.ssh/config`, same syntax as an
`~/.ssh/config` `ProxyJump` entry (`#[serde(default)]`, so older vault files
without it keep decrypting; not a secret, so it's fine to show in `Debug`
output).

**Out-of-band authorization flow (device-code style):** (1) the agent runs
`sloosh request <host>...` — a request must name specific hosts, since a
blanket "unlock everything" would reduce approval to a rubber stamp; before
creating the pending request, the daemon expands each named host's
`ProxyJump` chain (vault `jump` field and/or `~/.ssh/config` `ProxyJump`,
recursed the same way connection-time resolution does, same 8-hop cap) and
folds every hop alias into the request's host set, deduplicated, target
first — so the human approves coverage for the whole path, not just the
final target; (2) the daemon creates a pending request with a generated ID,
and the CLI prints one copy-pasteable approval command; (3) a human runs
that command in a **separate terminal**, entering the master password — a
pure-terminal flow that also works headless, and where first-time host-key
fingerprint confirmation happens, since a human is already present to judge
it; (4) the resulting lease auto-expires after an idle period, and
`request` for an already-covered host returns success immediately
(idempotent), so the agent never has to track lease state itself.

**Agent identity anchoring: process ancestry.** The primary mechanism
(`src/daemon/lease.rs`) binds a lease to a `(PID, process start time)`
pair — not a credential or token — identifying a process in the approving
caller's ancestry, guarding against PID reuse. *Anchor selection* happens
once, at `request` time: the daemon walks up the caller's process tree
(`src/procs/`, `sysctl` on macOS / `/proc` on Linux) to the human-meaningful
top-level agent process, skipping the `sloosh` CLI itself and intermediate
shells. *Anchor matching* — whether a later call is covered by an active
lease — never re-runs selection; it just checks whether the stored
`(pid, start_time)` appears anywhere in the current caller's ancestry, so
subagents spawned under an authorized process inherit the lease
automatically, while a genuine agent restart correctly requires
re-approval. The escape hatch is the `SLOOSH_LEASE` environment variable,
for cases where process-tree ancestry is broken (e.g. a detached process);
env vars inherit to children the same way ancestry does. Windows note (not
yet implemented): a dead parent's PID can be recycled, so a future Windows
port also needs to check that a child's creation time postdates its
claimed parent's.

**Trust posture and residual risk.** The `0600` same-user socket
permission is only the outer perimeter. Every host-touching request
(`Run`/`Peek`/`Send`/`Interrupt`/`Open`/`Kill`) independently requires an
active lease, checked daemon-side via `lease::check_authorized` — never
trusted from the client. `ssh.rs` applies the same check a second time,
per hop, while dialing a `ProxyJump` chain: right before opening the
`direct-tcpip` tunnel through a given hop, if that hop's credentials come
from the vault, the requesting process must independently hold a lease for
*that hop's* alias, not just the final target (a hop resolved purely from
`~/.ssh/config` uses ambient user credentials and needs no lease). Missing
coverage fails with a teaching error naming the specific hop and the
`sloosh request` invocation that covers it. This is enforced because the
CLI's TTY guards on
`approve`/`add`/`rm`/`vault init` only protect those specific entry
points; any other same-user process can write raw NDJSON straight to the
socket. Concretely, `ApproveLease` never creates the vault (a missing
vault is a hard error pointing at `sloosh vault init`) and rejects an
approver whose own ancestry contains the pending request's anchor
(self-approval). **Accepted residual risk** (documented in
`src/daemon/mod.rs`): a malicious same-user process that deletes
`~/.sloosh/vault` outright could race a fresh `vault init` with its own
password and self-serve future approvals — defending against a hostile
process running as the same OS user is outside what a same-user daemon can
do alone; true isolation needs OS help (keychain/biometric-gated key
storage), tracked as future work rather than claimed as solved.

**Audit log** (`src/daemon/audit.rs`) appends one NDJSON line per event to
`~/.sloosh/audit.jsonl` (`0600`, same posture as the socket/vault); the
daemon is the sole writer, and `sloosh log` reads the file directly (no
daemon round-trip). Recorded: authorization events (request/approve/
expiry, with agent identity and host scope), connection events
(established/disconnected, with cause), and operation events (each `run`'s
full command text, session, timestamp, exit code; `put`/`get` paths).
Command *output* is deliberately never logged — that's the spool's job.
Every call site funnels through one `record()` function, so "never log a
credential or output" only has one place to get right. Writing is
best-effort: a failure is `tracing::warn`-reported and swallowed rather
than blocking the operation — the log is a diagnostic aid under this
same-user threat model, not a security control that must never miss an
entry.

## 5. Platform support

Platform-specific code (IPC transport, process-tree walking, file
permissions, path conventions) must live behind an abstraction boundary —
`src/transport/`, `src/procs/` — rather than inline `cfg` branches
scattered through shared logic (DESIGN.md §2). Today that boundary has one
implementation each: macOS (`src/procs/macos.rs`, `sysctl`-based) and
Linux (`src/procs/linux.rs`, `/proc`-based), both on the Unix domain
socket transport. Windows support (a Named Pipe transport, plus the
PID-reuse-aware ancestry check from §4) is planned but not implemented.

## 6. Module layout

```
src/
  main.rs        entry point: CLI parsing, daemon subcommand dispatch
  cli/           clap command definitions, client-side logic, daemon auto-spawn
  proto.rs       NDJSON request/response/event types (serde)
  transport/     IPC abstraction trait; unix.rs (UDS); windows.rs (phase 2)
  daemon/
    mod.rs       accept loop, request routing
    session.rs   PTY sessions: sentinel framing, ring buffer, cursor, spool
    ssh.rs       russh connection setup, ~/.ssh/config subset, multi-hop ProxyJump,
                 IdentityAgent, known_hosts
    lease.rs     leases: process-ancestry anchoring, env escape hatch, idle timeout
    vault.rs     argon2id + ChaCha20-Poly1305, zeroize
    audit.rs     audit.jsonl append-only writer
  procs/         process-tree walking abstraction; macos.rs (sysctl); linux.rs (/proc)
skills/sloosh/   agent skill (SKILL.md, agentskills.io format; distributed
                 via the ReiSuzunami/nerv plugin marketplace and `npx skills`)
```

(DESIGN.md §8)
