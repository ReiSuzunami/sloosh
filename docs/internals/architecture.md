# Architecture

This document owns component boundaries, data ownership, and runtime behavior.
See [`../../SECURITY.md`](../../SECURITY.md) for guarantees, limits, and the
threat model. See [`protocol.md`](protocol.md) for exact wire messages, framing,
and sequencing.

## 1. Component and data ownership

```text
Agent process                         Human terminal
     |                                     |
     +---------------+---------------------+
                     v
          +------------------------+
          | sloosh CLI             |
          |                        |
          | - argument/TTY policy  |
          | - protocol handshake   |
          | - local file access    |
          | - Agent Skill setup    |
          | - approval preview     |
          | - routed key probes    |
          +-----------+------------+
                      |
                      | Unix domain socket
                      v
          +------------------------+
          | sloosh daemon          |
          |                        |
          | - peer PID + leases    |
          | - vault writer/cache   |
          | - SSH connections      |
          | - PTY sessions/spool   |
          | - remote SFTP handles  |
          | - forwards + audit     |
          +-----------+------------+
                      |
                      | SSH / SFTP
                      v
               Remote hosts
```

CLI and daemon are subcommands of one binary. Ordinary CLI commands start the
daemon when needed. The daemon is persistent because SSH connections, PTY
shells, forwards, pending approvals, and active leases must outlive one CLI
invocation. Restarting it loses this in-memory state and terminates sessions and
forwards.

Ownership is deliberate:

- CLI owns argument policy, human prompts, Agent Skill installation, approval
  preview, routed host-key probes, and every local filesystem operation for
  SFTP.
- Daemon owns authorization, long-lived SSH state, remote SFTP handles, PTYs,
  spool, forwards, vault mutation/cache, and audit appends.
- A transfer `local_path` crossing the socket is an audit/display label. Daemon
  never opens that caller-supplied local path.
- Human CLI temporarily unlocks its own vault cache during approval. Daemon has
  a separate cache and independently validates the approved host scope.
- On DMG-installed macOS, daemon may spawn bundled `Sloosh Approval.app` over
  anonymous pipes. Helper alone owns Keychain/Touch ID, secure PIN/Master
  Password entry, and native confirmation
  UI; daemon still owns host expansion and lease activation. Helper never
  listens on a socket and requesting process cannot send it approval messages.
- `sloosh skill install/status` is CLI-only and never starts the daemon or
  accesses the vault. `sloosh init` requires a real TTY, installs/verifies the
  embedded Skill, then enters the existing vault initialization flow. These
  steps are deliberately restartable rather than transactional.
- `gui/` is a Svelte 5 frontend inside a Tauri 2 desktop process. It owns
  presentation, fixed setup commands, and host-management forms. Host inventory
  and mutations still cross the verified daemon seam. Master Password, Touch ID,
  and PIN unlock create a time-bounded desktop session containing one zeroizing
  `SecretString` in Rust memory; only status and countdowns enter the WebView.
  Its idle timeout comes from the same owner-only `vault-settings.json` used by
  daemon leases, while each Agent request still needs its own exact-scope human
  approval. SSH Password is transient WebView state, crosses the local Tauri
  command boundary as `SecretString`, and is cleared after submission. The
  bundle keeps the CLI/daemon as `Helpers/sloosh`.

## 2. Local transport boundary

`src/transport/` defines the `Channel` abstraction. macOS and Linux use Unix
domain sockets implemented by `src/transport/unix.rs`; Windows Named Pipes are
not implemented.

Default socket locations:

- Linux: `$XDG_RUNTIME_DIR/sloosh.sock`, falling back to
  `/tmp/sloosh-<euid>/sloosh.sock`.
- macOS: `$SLOOSH_HOME/sloosh.sock`, normally `~/.sloosh/sloosh.sock`.
- `$SLOOSH_SOCKET` overrides either default.

Before sending requests, CLI verifies that daemon peer eUID matches its own and
that peer executable resolves to the current `sloosh` executable. Daemon gets
client PID from kernel peer credentials (`SO_PEERCRED` on Linux,
`LOCAL_PEERPID` on macOS) and uses it for authorization and self-approval
checks.

These checks authenticate daemon to CLI and identify client process to daemon.
They do not isolate hostile code already running as the same UID. A same-UID
process can open the socket, but ordinary requests still require protocol
negotiation and daemon-side capability checks.

The macOS DMG installer is a narrow additional local client during upgrades.
It sends only the pre-negotiation `Shutdown` request to the default private
socket before replacing an existing recognized app. It never negotiates,
accesses credentials, or sends an ordinary request, and it never executes the
old installed bundle.

Protocol 3 uses bounded NDJSON control messages and bounded raw frames for SFTP
payloads. CLI performs `Status -> Hello -> ProtocolReady`; daemon rejects
unnegotiated ordinary requests before side effects. `protocol.md` owns exact
limits, allowed pre-negotiation messages, transfer state machines, and upgrade
behavior.

## 3. Authorization and stable grants

### Process ancestry lease

`src/daemon/lease.rs` anchors a request to a process instance identified by PID
plus kernel start time. Linux clock-tick and macOS microsecond precision are
retained so PID reuse within one second does not identify the same process.
Later callers inherit authorization when that exact anchor appears in their
ancestry. `SLOOSH_LEASE` is a bearer-token escape hatch for detached process
trees.

An active lease grants a set of host aliases. API entry points prune expired
state before use; background reapers clean otherwise-idle state and clear the
vault cache after the last lease ends. The idle limit is the shared 1/5/15/30
minute vault timeout; the daemon reads it independently and retains its separate
8-hour hard lifetime cap. Exact lifetimes and reaper intervals belong to
`SECURITY.md`.

### Stable `LeaseGrant`

A short-lived CLI PID cannot own a background forward. At creation,
`lease::resolve_grant` converts caller ancestry/token authorization into an
opaque `LeaseGrant` scoped to one host and active lease. The forward stores this
grant rather than creator PID.

Accepted traffic calls `check_grant`, revalidating the lease and refreshing its
idle clock. Reapers use `peek_grant`, which checks without refreshing.

Lease expiry has three intentional outcomes:

- PTY session stays alive but becomes inaccessible until re-approved.
- Forward and existing tunnels close because they are live network access.
- SFTP already past `TransferReady` may complete under its start-time grant;
  later operations need a new live lease.

## 4. Approval, ProxyJump, and host keys

Request-time host scope may be incomplete while vault is locked. Approval
therefore resolves scope independently on human and daemon sides:

```text
agent CLI       daemon                         human CLI
    | Request     |                                |
    +------------>| pending scope                  |
    |              |<----------- Describe ---------+
    |              |---------- request details --->|
    |              |                      unlock + expand
    |              |                      confirm exact list
    |              |<-- Approve(password, list) ---+
    |              | unlock + independently expand
    |              | exact ordered comparison
    |              |---------- result ------------>|
```

Mismatch or invalid route resolution fails closed and leaves an existing
pending request available for corrected approval. If a cycle or over-depth
route is visible before pending state is created, `RequestLease` fails instead
of presenting a truncated approval scope. Connection-time dialing also checks
each vault-backed ProxyJump alias independently.

DMG-installed macOS adds an internal adapter without changing wire protocol:

```text
agent CLI          daemon                    native helper
    | Request        |                            |
    +--------------->| create pending            |
    |                 |---------- begin --------->|
    |                 |<------ password ----------| login Keychain
    |                 | unlock + expand exact list|
    |                 |---------- list ---------->|
    |                 |       human confirms      |
    |                 |<-- Touch ID or PIN --------| native secure input
    |                 | compare again + activate  |
    |<------ Ok ------|                            |
```

PIN verification is a daemon-local state machine with persistent backoff. It
does not alter the request's Master Password failure budget. Cancellation,
missing enrollment, helper failure, or any unknown SSH host key
keeps request pending and returns normal terminal-approval instructions. Native
success uses existing `RequestLease -> Ok`; bearer lease token never returns to
requesting process. Password approval remains supported on every platform.

After activation, human CLI confirms missing host keys in dependency order.
Each jump is trusted before targets reached through it. A target probe follows
the real ProxyJump route: intermediate hops use strict verification and normal
authentication; only final unknown target captures a key, stopping before
authentication. Rejection or probe failure records nothing.

## 5. SSH sessions and output

`src/daemon/session.rs` keeps one PTY shell per `(host, session)`. Commands use
random sentinels inside shared PTY byte stream. Stateful scrubber handles split,
stale, and interrupt-resync markers before output becomes visible.

Session state contains an in-memory output ring, active run framing state,
connection/dead state, activity timestamps, and one spool writer for active
run. `run` returns `done`, `running`, or `dead`. Timeout reports `running`
without killing command. Disconnect reports `dead`; daemon never silently
creates a fresh shell with different state.

Spool is bounded retention, not complete archive. It uses an actual-byte ledger,
protects active files, creates retained files collision-safely, and avoids
full-tree scans at each run boundary. Incomplete initial indexing pauses new
persistence until retry rather than granting against unknown disk use. Cleanup
failure can stop further persistence but must not fail command or erase active
output. Synchronous spool I/O may still delay PTY consumption on slow storage.
Exact memory/disk limits and file guarantees belong to `SECURITY.md`.

## 6. SFTP ownership

Both directions open a new SFTP channel on an existing authenticated SSH
connection. CLI owns local file descriptor; daemon owns remote handle. Lease is
checked before `TransferReady` and then fixed for that stream.

For `put`, CLI opens local source and daemon creates or truncates remote target.
Upload is not a remote atomic replacement; interruption may leave partial data.

For `get`, CLI creates a same-directory temporary file. Only final successful
`Transfer` causes sync and atomic local commit. Existing destination is
preserved on normal failure, and overwrite requires `--force`.

Raw frame format, completion ordering, interruption behavior, and error
transitions belong to `protocol.md`. Filesystem guarantees and timeout policy
belong to `SECURITY.md`.

## 7. Forwarding

`src/daemon/forward.rs` implements local and remote forwarding:

- `-L` binds loopback only.
- `-R` creates a server-side listener whose exposure follows sshd
  `GatewayPorts` policy.
- Each forward owns dedicated SSH connection and stable `LeaseGrant`.
- Accepted traffic revalidates grant.
- Remote route is monotonic `Pending -> Active -> Closed`; only `Active` may
  dial local target.
- Stop or expiry closes route before awaiting bounded remote cancellation, then
  drops dedicated connection even if server never acknowledges.
- Connection loss, explicit stop, or lease expiry closes forward.

Non-loopback `-L` remains rejected. Remote listener is broader capability but
is deliberately covered by host lease and must be requested explicitly.

## 8. Vault lifecycle

`src/daemon/vault.rs` serializes disk mutation and async cache publication with
separate locks. Disk transaction lock prevents concurrent add/remove from
losing entries. Async mutation lock prevents older unlock/cache refresh from
overwriting newer state.

Unlock reads one vault envelope, derives key from that envelope's KDF data,
decrypts its ciphertext, then publishes cache material together. Saves use
fresh cryptographic material and atomic temp-file rename. Daemon cache is
cleared after last lease expires. Exact cryptography, permissions, symlink/ACL
checks, and zeroization guarantees belong to `SECURITY.md`.

Vault format 2 stores an explicit authentication method and route per host.
Authentication is exactly one of SSH agent, encrypted password, or an
unencrypted private-key path; vault profiles do not silently fall back to a
different method. Routing is exactly direct, through another managed profile,
or an advanced OpenSSH ProxyJump expression. Version-1 entries are accepted:
missing `jump` becomes direct and a legacy string becomes advanced ProxyJump;
the next mutation rewrites the envelope as version 2. Vault mutation rejects
missing managed hosts, managed-route cycles, over-depth chains, and removal of
a profile still referenced by another managed route. `src/daemon/ssh.rs`
repeats ProxyJump cycle/depth enforcement before dialing and owns lease and
host-key ordering.

## 9. Module map

```text
src/
  main.rs            process entry and command dispatch
  cli/
    args.rs          clap surface
    client.rs        daemon connect/spawn, peer and protocol checks
    mod.rs           CLI behavior, local SFTP files, setup, approval UI
    skill.rs         embedded Agent Skill, target detection, safe install/status
  proto.rs           protocol request/response types and NDJSON limit
  transport/
    mod.rs           Channel and raw-frame contract
    unix.rs          UDS, peer credentials, paths and permissions
  daemon/
    mod.rs           accept loop and request routing
    lease.rs         pending requests, active leases, stable LeaseGrant
    vault.rs         encrypted vault, serialized mutation, cache
    ssh.rs           SSH transport/auth facade, ProxyJump, host-key verification
    ssh/config.rs    OpenSSH config subset parsing and deterministic resolution
    ssh/route.rs     remote-forward route lifecycle and byte-pump mechanics
    session.rs       PTY state, sentinel framing, spool, SFTP handles
    forward.rs       local -L, remote -R, and forward lifetime
    audit.rs         best-effort audit append/read helpers
  native_approval.rs daemon-side native approval port and helper protocol
  local_approval.rs  PIN verifier, persistence, backoff, and disable policy
gui/
  src/               Svelte status and setup UI; no secret fields
  src-tauri/         fixed desktop command allowlist and bundle configuration
  procs/
    macos.rs         process ancestry via macOS APIs
    linux.rs         process ancestry via /proc
```
