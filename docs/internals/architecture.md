# Architecture

This document owns component boundaries, data ownership, and runtime behavior.
See [`../../SECURITY.md`](../../SECURITY.md) for guarantees, limits, and the
threat model. See [`protocol.md`](protocol.md) for exact wire messages, framing,
and sequencing.

## 1. Component and data ownership

```text
Agent process + human terminal              Human desktop
              |                                  |
              v                                  v
    +------------------------+        +------------------------+
    | sloosh CLI             |        | Sloosh Tauri app       |
    | - argument/TTY policy  |        | - native control plane |
    | - local SFTP files     |        | - setup/security/hosts |
    | - Agent Skill setup    |        | - no public CLI        |
    +------------+-----------+        +-----------+------------+
                 |                                |
                 +---------------+----------------+
                                 |
                                 | verified Unix domain socket
                                 v
                     +------------------------+
                     | slooshd                |
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

`sloosh` and the desktop app are separate clients of the dedicated `slooshd`
binary. Neither client routes control operations through the other. Ordinary
CLI or desktop commands start the selected daemon when needed. The daemon is
persistent because SSH connections, PTY shells, forwards, pending approvals,
and active leases must outlive one client invocation. Restarting it loses this
in-memory state and terminates sessions and forwards.

Ownership is deliberate:

- CLI owns argument policy, terminal human prompts, Agent Skill installation,
  approval preview, routed host-key probes, and every local filesystem
  operation for SFTP.
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
  and mutations cross the same verified daemon seam as the CLI; the app never
  shells out to `sloosh`. Master Password, Touch ID, and PIN unlock create a
  time-bounded desktop session containing one zeroizing `SecretString` in Rust
  memory; only status and countdowns enter the WebView.
  Its idle timeout comes from the same owner-only `vault-settings.json` used by
  daemon leases, while each Agent request still needs its own exact-scope human
  approval. SSH Password is transient WebView state, crosses the local Tauri
  command boundary as `SecretString`, and is cleared after submission. Host
  form serialization sends SSH Password or key-file path only while adding a
  profile or explicitly changing its authentication; ordinary edits send
  neither. The key-file path may be typed directly or selected with the native
  file picker. Hosts also provides a human-only host-key bootstrap that
  re-probes a confirmed endpoint/fingerprint before recording it, plus an
  end-to-end connection test that uses an ordinary daemon lease and a
  short-lived reserved PTY session. On macOS, the desktop process maps Tauri's
  system-theme events to
  explicit light/dark AppKit Dock icons while the bundle icon remains the
  launch-time fallback. The bundle keeps only its private daemon at
  `Helpers/slooshd`; it contains no public `sloosh` CLI and creates no CLI link.

The command-line distribution always keeps `sloosh` and `slooshd` in the same
directory. On Linux and CLI-only macOS installations, the client selects that
sibling daemon. A macOS release CLI instead selects
`/Applications/Sloosh.app/Contents/Helpers/slooshd` when present; source/debug
builds keep using their build-tree sibling. The GUI always selects the helper
inside its own bundle. Before selecting an app helper, both clients validate
the bundle-to-helper path components, ownership, write permissions, file type,
and executable mode. This deterministic rule lets Homebrew/Cargo/archive
clients and the installed desktop share one daemon without trusting `PATH`
lookup.

## 2. Local transport boundary

`src/transport/` defines the `Channel` abstraction. macOS and Linux use Unix
domain sockets implemented by `src/transport/unix.rs`; Windows Named Pipes are
not implemented.

Default socket locations:

- Linux: `$XDG_RUNTIME_DIR/sloosh.sock`, falling back to
  `/tmp/sloosh-<euid>/sloosh.sock`.
- macOS: `$SLOOSH_HOME/sloosh.sock`, normally `~/.sloosh/sloosh.sock`.
- `$SLOOSH_SOCKET` overrides either default.

Before sending ordinary requests, each client verifies that daemon peer eUID
matches its own and that the peer executable resolves to its explicitly
selected `slooshd` canonical path. Daemon gets client PID from kernel peer
credentials (`SO_PEERCRED` on Linux, `LOCAL_PEERPID` on macOS) and uses it for
authorization and self-approval checks.

These checks authenticate daemon to CLI and identify client process to daemon.
They do not isolate hostile code already running as the same UID. A same-UID
process can open the socket, but ordinary requests still require protocol
negotiation and daemon-side capability checks.

`sloosh daemon stop` and the macOS DMG installer are narrow recovery clients.
They send only the pre-negotiation `Shutdown` request to the private socket,
even if the selected daemon executable is missing or incompatible. They never
negotiate, access credentials, or send an ordinary request; the installer also
never executes the old installed bundle.

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

`src/daemon/ssh/config.rs` parses without logging. It attaches normalized,
value-free diagnostics to global or `Host` scopes, then surfaces only those
selected after vault precedence and host-pattern matching. Direct vault
profiles therefore ignore unrelated OpenSSH configuration. Unsupported
directives known to change a selected stanza's route or host-key identity and
invalid selected ports return typed errors. `Include` is also fail-closed
because ignored files could replace endpoint, route, or trust settings.
`Match` begins an independent conditional section; because Sloosh does not
evaluate its predicates, any `Match` is a global fail-closed barrier for
SSH-config-backed hosts. Lower-impact ignored options emit one stable-code
warning. Human CLI plans the complete host-key confirmation route before
sending `ApproveLease`, so a planning failure cannot activate a lease.

DMG-installed macOS adds an internal adapter without changing wire protocol:

```text
agent CLI          daemon                    native helper
    | Request        |                            |
    +--------------->| create pending            |
    |                 |---------- begin --------->|
    |                 |<------ password ----------| login Keychain
    |                 | unlock + expand exact list|
    |                 |---------- list ---------->|
    |                 | human confirms + chooses  |
    |                 |<-- Touch ID/PIN/Master ----| native secure input
    |                 | compare again + activate  |
    |<------ Ok ------|                            |
```

PIN verification is a daemon-local state machine with persistent backoff. It
does not alter the request's Master Password failure budget. A Master Password
selected in native UI is verified by reopening the vault, then the daemon
recomputes and compares the exact host scope before activation. Cancellation,
missing enrollment, helper failure, or any unknown SSH host key keeps the
request pending. The human may bootstrap missing keys in the terminal approval
flow or from the unlocked desktop Hosts screen, then retry. Native success uses
existing `RequestLease -> Ok`; bearer lease token never returns to the
requesting process. Password approval remains supported on every platform.

Human CLI approval, `sloosh host trust`, and the desktop Hosts trust flow
inspect host keys in dependency order. Each jump is trusted before targets
reached through it. A target probe follows the real ProxyJump route:
intermediate hops use strict verification and normal authentication; only the
final actionable target captures a key, stopping before authentication.

The shared trust state is `Trusted`, `Unknown`, or `Changed` with an owning
source. A simple changed entry owned by `~/.sloosh/known_hosts` is replaceable;
a mismatch owned by `~/.ssh/known_hosts` is displayed but never mutated.
Before Add or Replace, the process repeats route resolution and probing and
requires the entire human-visible preview, including old and new
fingerprints, to match. Sloosh then locks its private trust store, verifies the
expected old state, and atomically renames a mode-0600 replacement. Rejection,
stale state, probe failure, or a failure before rename records nothing. Rename
is the commit point; a later parent-directory sync failure is logged as a
durability warning without reporting the visible change as failed.

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
output. Initial spool-open or later write failure detaches persistence for that
run, leaves `spool_path` empty when no file was created, and still allows the
command and bounded in-memory ring to proceed. Synchronous spool I/O may still
delay PTY consumption on slow storage.
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
unencrypted Ed25519/ECDSA private-key path; vault profiles do not silently fall
back to a different method. RSA and encrypted private keys stay usable through
ssh-agent, but local RSA signing is rejected because the available
implementation has a timing side channel. Routing is exactly direct, through
another managed profile, or an advanced OpenSSH ProxyJump expression.
Version-1 entries are accepted:
missing `jump` becomes direct and a legacy string becomes advanced ProxyJump;
the next mutation rewrites the envelope as version 2. Vault mutation rejects
missing managed hosts, managed-route cycles, over-depth chains, and removal of
a profile still referenced by another managed route. `src/daemon/ssh.rs`
repeats ProxyJump cycle/depth enforcement before dialing and owns lease and
host-key ordering.

## 9. Module map

```text
src/
  main.rs            process entry
  cli/
    args.rs          clap surface
    client.rs        daemon connect/spawn, peer and protocol checks
    mod.rs           command dispatch and restartable setup orchestration
    daemon_cmd.rs    daemon lifecycle and status display
    approval.rs      TTY policy, vault setup, approval preview, key probes
    host.rs          vault-backed host inventory and credential enrollment
    session.rs       PTY session command clients and rendering
    transfer.rs      CLI-owned local SFTP files and raw-frame streaming
    forward.rs       forwarding command client and rendering
    log.rs           bounded audit-log query and rendering
    skill.rs         embedded Agent Skill, target detection, safe install/status
  proto.rs           protocol request/response types and NDJSON limit
  vault_settings.rs  shared owner-only idle-timeout preference
  procs/
    macos.rs         process ancestry via macOS APIs
    linux.rs         process ancestry via /proc
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
    session.rs       PTY state, sentinel framing, registry, SFTP facade
    session/sftp.rs  remote-only SFTP channels and bounded transfer handles
    session/spool.rs bounded spool writer, actual-byte ledger, retention
    forward.rs       local -L, remote -R, and forward lifetime
    audit.rs         best-effort audit append/read helpers
  native_approval.rs daemon-side native approval policy and cache cleanup
  native_approval/
    helper.rs        validated helper process and bounded anonymous-pipe IPC
  local_approval.rs  PIN verifier, persistence, backoff, and disable policy
gui/
  src/               Svelte status, setup, and transient host forms
    hostForm.ts      pure host validation and command serialization
  src-tauri/         fixed desktop command allowlist and bundle configuration
    dock_icon.rs     macOS Dock icon synchronization with system appearance
    host_commands.rs vault-backed host command boundary
```
