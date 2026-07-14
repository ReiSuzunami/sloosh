# Architecture

This document describes the code as implemented. See
[`../DESIGN.md`](../DESIGN.md) for the Chinese design/status document,
[`../SECURITY.md`](../SECURITY.md) for the threat model, and
[`PROTOCOL.md`](PROTOCOL.md) for the exact local wire framing.

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
          | - approval preview     |
          | - routed key probes    |
          +-----------+------------+
                      |
                      | Unix domain socket
                      | control: NDJSON <= 1 MiB
                      | data: length-prefixed raw frames
                      v
          +------------------------+
          | sloosh daemon          |
          |                        |
          | - peer PID + leases    |
          | - vault writer/cache   |
          | - SSH connections      |
          | - PTY sessions/spool   |
          | - remote SFTP handles  |
          | - local forwards       |
          | - audit writer         |
          +-----------+------------+
                      |
                      | SSH / SFTP
                      v
               Remote hosts
```

The CLI and daemon are subcommands of one binary. The daemon is persistent
because PTY shells, forwards, pending approvals, and active leases must outlive
one short CLI invocation. If no daemon is reachable, ordinary CLI commands
spawn `sloosh daemon run` detached; bind atomicity decides concurrent startup
races.

Ownership is deliberate:

- The CLI owns every local filesystem operation for SFTP. It opens an upload
  source or a download temp file under its own cwd/sandbox. A `local_path` sent
  to the daemon is an audit/display label only.
- The daemon owns the remote SFTP handle and moves bytes between raw UDS frames
  and that handle. It never opens the caller-supplied local path.
- The daemon is the normal vault writer and owns the long-lived unlocked cache.
  During `approve`, the human CLI temporarily unlocks its own read cache so it
  can preview vault-only ProxyJump entries and run routed host-key probes. That
  CLI cache is cleared when approval processing ends.
- The daemon owns all long-lived SSH connections, PTYs, spool writers,
  forwards, leases, and audit appends. Restarting it loses all in-memory state
  and terminates active sessions and forwards.

## 2. Local transport and protocol boundary

`src/transport/` defines the `Channel` interface. The current implementation is
Unix domain sockets in `src/transport/unix.rs` for macOS and Linux. Windows
Named Pipes are not implemented.

Socket locations are:

- Linux: `$XDG_RUNTIME_DIR/sloosh.sock`, or
  `/tmp/sloosh-<euid>/sloosh.sock` when no runtime directory is available.
- macOS: `$SLOOSH_HOME/sloosh.sock`, normally `~/.sloosh/sloosh.sock`.
- `$SLOOSH_SOCKET` overrides either path.

Sloosh-managed parents are created or repaired to mode `0700`, and the socket
is set to `0600`. A non-default parent selected through `$SLOOSH_SOCKET` is
validated but never mutated: it must already be owned by the current eUID and
have mode `0700`; on macOS it must also have no extended ACL.
Before sending a request, `UnixChannel::connect` checks that the server peer has
the current effective UID and the same canonical executable path as the current
`sloosh` process. This is useful daemon authentication, but it is not a defense
against hostile code already running as the same user; see `SECURITY.md`.

The daemon obtains the client PID from kernel peer credentials:

- Linux: `SO_PEERCRED`.
- macOS: `LOCAL_PEERPID`, with `getpeereid` available to the transport.

The daemon uses the PID for lease ancestry and self-approval checks. It does
not require clients to be the `sloosh` executable. A same-UID process can open
the socket, but must complete the protocol 1 `Hello` gate before ordinary
requests and remains subject to daemon-side capability checks.

### Protocol 1

Protocol 1 is mixed framing, not pure NDJSON:

```text
ordinary request:  NDJSON request -> NDJSON response

Put/Get request:   NDJSON request -> NDJSON TransferReady
                    raw frames ... -> zero-length raw frame
                    NDJSON Transfer or Error
```

Each control line, including its newline, is limited to 1 MiB. Each raw frame
has a 4-byte big-endian unsigned length and at most 1 MiB of payload. Length 0
means stream EOF. A stream can contain any number of frames, so SFTP transfers
have no application total-size cap.

Protocol 1 uses a bidirectional gate. The CLI first sends `Status` and requires
an exact `wire_protocol` match, then sends `Hello { wire_protocol: 1 }`. The
daemon replies `ProtocolReady { wire_protocol: 1 }` and marks that connection
negotiated. Before this exchange, the daemon allows only `Status`, `Hello`, and
`Shutdown`. Every ordinary request is rejected before request-specific side
effects. A wrong-version `Hello` leaves the gate closed.

`sloosh daemon stop` intentionally uses the pre-negotiation `Shutdown` path so
an old daemon can be stopped during upgrade. A raw client cannot skip the
server gate for ordinary requests.

NDJSON remains readable, but `nc -U` is not a complete or supported client: it
does not authenticate the daemon executable or automatically implement the
`Status`/`Hello` exchange, raw transfer framing, and sequencing.

## 3. Authorization and stable grants

### Process ancestry lease

`src/daemon/lease.rs` stores pending requests and active leases in memory. A
request is anchored to a process instance identified by PID plus start time.
The platform readers retain Linux clock-tick or macOS microsecond precision so
same-PID instances with distinct kernel timestamps remain distinct, including
within one second. Later callers inherit authorization when that exact anchor
appears in their current ancestry. `SLOOSH_LEASE` is a bearer-token escape hatch
for detached process trees.

An active lease grants a set of host aliases. It expires after either:

- 2 hours without a matching operation, or
- 8 hours absolute lifetime.

API entry points prune before use, and a 60-second background reaper clears
otherwise-idle expired leases and the vault cache after the last lease is gone.
Pending requests expire after 15 minutes.

### Stable `LeaseGrant`

A CLI PID is short-lived and cannot identify a background forward. At forward
creation, `lease::resolve_grant` converts current ancestry/token authorization
to an opaque `LeaseGrant` scoped to one host and one active lease. The forward
stores this stable grant, not the creator CLI PID.

Real accepted forward traffic calls `check_grant`, which revalidates the lease
and refreshes its idle clock. The 15-second forward reaper calls `peek_grant`,
which revalidates without refreshing. Once the lease expires, the registry
removes the forward and the owner task closes the listener and existing
tunnels.

PTY sessions intentionally differ: lease expiry blocks access but does not
kill the remote shell. A later lease can reconnect to the still-live session.

An SFTP transfer is one operation authorized before `TransferReady`. Once its
remote handle is open and the stream starts, it retains that start-time grant.
Idle or absolute expiry blocks later transfers but does not abort the current
one. This prevents the 8-hour absolute lease lifetime from becoming a NAS
transfer duration or file-size limit.

## 4. Approval, ProxyJump, and host keys

The approval path resolves host scope twice because a request may be created
while the vault is locked:

```text
agent CLI             daemon             human CLI
    |                    |                    |
    | RequestLease       |                    |
    +------------------->|                    |
    | pending host list  |                    |
    |<-------------------+                    |
    |                    | DescribeRequest    |
    |                    |<-------------------+
    |                    |------------------->| prompt + details
    |                    |                    | unlock local vault cache
    |                    |                    | expand ProxyJump list
    |                    |                    | human confirms exact list
    |                    | ApproveLease(password, approved_hosts)
    |                    |<-------------------+
    |                    | unlock daemon cache
    |                    | independently re-expand
    |                    | exact list compare
    |                    |                    |
    |                    | LeaseActivated or Error
    |                    |------------------->|
```

The list comparison includes order and fails closed. A stale or omitted
`approved_hosts` list does not activate a lease, and the pending request remains
available for a corrected approval. Connection-time dialing also checks every
vault-backed jump alias independently.

After activation, the human CLI confirms missing host keys in dependency order.
`ssh::host_key_confirmation_order` produces each jump before targets that need
it. A target probe follows the same resolved ProxyJump route as a real
connection:

- Intermediate hops use normal strict host-key verification and normal
  authentication.
- The final unknown target accepts a key only inside a capture handler, stops
  after key exchange, and is not authenticated.
- The human confirms the displayed SHA256 fingerprint before the CLI records
  it in `~/.sloosh/known_hosts`.
- Probe failure or rejection records nothing. Real connections continue to
  reject an unknown or mismatched key.

This is routed bootstrap, not blind trust. Fingerprints still need an
independent source when route compromise is a concern.

## 5. SSH sessions and output

`src/daemon/session.rs` keeps one PTY shell for each `(host, session)` pair.
Commands are framed with random sentinels in the shared PTY byte stream. A
stateful scrubber removes complete, split, stale, and interrupt-resync markers
before bytes enter user-visible output.

The session state includes:

- a 256 KiB ring for cursor-based `peek`;
- one active run and its sentinel/resync state;
- connection/dead state and last activity;
- one bounded spool writer for the active run.

`run` returns `done`, `running`, or `dead`. Timeout reports `running` without
killing the command. Disconnects report `dead` and never silently recreate a
shell with different state. An 8-hour idle threshold is checked by a 5-minute
session reaper.

Reply output keeps roughly the final 30,000 characters. Spool is bounded
retention, not a complete archive:

- one run file retains at most 64 MiB of raw output and appends a visible limit
  marker when that per-run cap is reached; global exhaustion may leave too
  little room for a marker;
- one session directory has a 64 MiB retention budget, with oldest files
  removed on best-effort cleanup;
- the spool root has a 1 GiB hard application budget across every host and
  session, charged by actual persisted bytes;
- active runs protect their current files but reserve no unused allowance;
- one lazy root scan seeds a per-root ledger, then writes update it
  incrementally instead of rescanning the full tree at every run boundary;
- an incomplete scan pauses new persistence and retries after a 30-second
  backoff rather than granting against unknown retained bytes;
- when real output needs room, cleanup protects active paths and deletes the
  oldest inactive files by modification time across session directories;
- an unlink failure is logged and retried on a later pass. It may stop further
  persistence at the cap, but is not returned as a command failure and never
  deletes an active file;
- command/ring logic remains available after the disk cap, but synchronous
  append/eviction can still delay the PTY reader and other writers on a slow
  spool filesystem;
- run files use collision-safe `create_new`; reused sequence numbers get a
  unique suffix instead of truncating retained history;
- encoded host/session components prevent path traversal;
- directories are `0700`, and spool files are `0600` with `O_NOFOLLOW`.

These limits apply only to PTY command-output spool. They do not cap SFTP
transfer bytes or duration.

## 6. SFTP stream ownership

Both transfers open a new SFTP subsystem channel on an existing authenticated
SSH connection. The client config replaces `russh-sftp`'s default 10-second
per-request timeout with the pinned Tokio release's far-future deadline
(roughly 30 years). That is operationally unbounded for slow NAS work, while
SSH, server, filesystem, and network failures still surface normally.

### Put

1. CLI resolves and opens a local regular file.
2. CLI sends `Put` with `local_path` as a label.
3. Daemon checks the lease, opens remote `CREATE | TRUNCATE | WRITE`, and returns
   `TransferReady`.
4. CLI streams raw frames; daemon writes them under the start-time grant until
   raw EOF or a transfer error.
5. Zero-length frame ends the stream; daemon shuts down the remote handle and
   returns `Transfer` or `Error`.

An interrupted upload can leave a truncated or partial remote file. There is no
resume or remote atomic-replace layer.

### Get

1. CLI creates a temp file in the destination directory with requested mode
   `0666`; the caller's umask determines its effective mode.
2. Daemon checks the lease, opens the remote file, and returns `TransferReady`.
3. Daemon reads remote SFTP data into bounded frames; CLI writes the temp file.
4. Daemon sends raw EOF, then `Transfer` or `Error`.
5. Only after `Transfer` does the CLI sync and atomically commit the temp file.

Without `--force`, a hard link creates the destination only if absent. With
`--force`, same-directory rename replaces it. A normal error leaves an existing
destination untouched and removes the temp file; abrupt process termination can
leave an orphan temp file.

For both directions, the grant is fixed before `TransferReady`. Lease expiry
during the stream does not interrupt it; only a later transfer needs a new live
lease. Total bytes remain unlimited while each raw frame remains at most 1 MiB.

## 7. Forwarding

`src/daemon/forward.rs` implements local and remote forwarding:

- `-L` binds only loopback IP addresses. Omitted bind address is
  `127.0.0.1`; non-loopback literals fail before network access.
- `-R` asks the SSH server to create `[bind_addr:]remote_port` and routes each
  accepted connection to `local_host:local_port`. Port `0` requests a
  server-assigned port.
- Each forward has a dedicated SSH connection and stable `LeaseGrant`.
- Every accepted local or remote connection revalidates and touches that
  grant. Remote exposure follows the server's `GatewayPorts` policy.
- A remote route is monotonic `Pending -> Active -> Closed`; server-initiated
  channels are rejected outside `Active`. Local target connection races route
  closure and has a 10-second timeout, followed by a final grant/state check.
- Stop or expiry marks the route `Closed` first, bounds remote cancellation to
  2 seconds, then drops the dedicated SSH connection even if the server never
  acknowledges cancellation.
- Connection loss, explicit stop, or lease expiry closes the forward.
- `forward ls` is read-only and `forward stop` only reduces access, so neither
  requires a lease.

Non-loopback `-L` remains rejected. `-R` is deliberately covered by the host
lease, but its server-side listener is a broader capability that callers must
request intentionally.

## 8. Vault mutation and cache lifecycle

`src/daemon/vault.rs` stores a versioned JSON envelope containing Argon2id
parameters, a nonce, and ChaCha20-Poly1305 ciphertext. There is no separate
password verifier; successful AEAD decryption verifies the password.

Mutation and lease unlock use two serialization layers:

- a process-wide writer mutex covers each disk read-modify-write transaction;
- one async mutation mutex is shared by add/remove, cache refresh, and
  `unlock_for_lease` publication.

This prevents concurrent add/remove operations from losing an entry on disk or
allowing an older unlock/cache refresh to overwrite newer state. Lease unlock
reads one `VaultFile` envelope, derives the key from that envelope's KDF data,
decrypts that same envelope's nonce/ciphertext, and publishes all cache material
together. It never combines material from two disk snapshots. Saves use a fresh
salt and nonce, a random `create_new` mode-`0600` temp file, and atomic rename.

The daemon cache contains decrypted entries, KDF metadata, and a zeroizing
derived key. Approval populates it; add/remove refresh it only if already
present; the last lease expiry clears it. Password buffers, plaintext buffers,
keys, and vault entry passwords use zeroization where their Rust ownership
permits it.

## 9. Module map

```text
src/
  main.rs            process entry and command dispatch
  cli/
    args.rs          clap surface
    client.rs        daemon connect/spawn, peer and protocol checks
    mod.rs           CLI behavior, local SFTP files, approval UI
  proto.rs           protocol 1 request/response types and NDJSON limit
  transport/
    mod.rs           Channel and raw-frame contract
    unix.rs          UDS, peer credentials, paths and permissions
  daemon/
    mod.rs           accept loop and request routing
    lease.rs         pending requests, active leases, stable LeaseGrant
    vault.rs         encrypted vault, serialized mutation, cache
    ssh.rs           config resolution, ProxyJump, host-key verification
    session.rs       PTY state, sentinel framing, spool, SFTP handles
    forward.rs       local -L, remote -R, and forward lifetime
    audit.rs         best-effort audit append/read helpers
  procs/
    macos.rs         process ancestry via macOS APIs
    linux.rs         process ancestry via /proc
```
