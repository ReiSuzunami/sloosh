# Local Wire Protocol

This document specifies the current local client-to-daemon wire contract used
by both `sloosh` and the desktop app. The exact
version constant is `WIRE_PROTOCOL_VERSION = 3` in `src/proto.rs`.

Protocol 3 is local IPC over a Unix domain socket. It combines NDJSON control
messages with bounded binary frames for SFTP data. It is not a network API and
has no compatibility promise for arbitrary raw clients.

## 1. Version rule

Wire compatibility is exact, independent of package version. Any incompatible
message shape, tag, default, or sequencing change must bump the wire protocol
version.

For ordinary new client connections:

1. Client authenticates the daemon peer by eUID and the selected canonical
   `slooshd` executable path.
2. Client sends `{"type":"Status"}\n` as the first request.
3. Daemon returns a `Status` response containing `wire_protocol`.
4. Client requires an exact value of `3`.
5. Client sends `{"type":"Hello","wire_protocol":3}\n`.
6. Daemon replies
   `{"type":"ProtocolReady","wire_protocol":3}\n` and marks that connection
   negotiated.
7. Only then may the client send an ordinary request on that connection.

This is a bidirectional protocol gate:

- before successful `Hello`, the daemon permits only `Status`, `Hello`, and
  `Shutdown`;
- every other request is rejected before request-specific side effects;
- a wrong-version `Hello` returns `Error` and leaves the connection
  unnegotiated;
- `Status` may be used without opening the gate and does not itself negotiate;
- the daemon does not select among protocol versions; exact equality is
  required in both directions;
- a legacy status response with no `wire_protocol` deserializes as `0` and is
  rejected by a new CLI;
- a raw same-UID client cannot skip the server gate for ordinary requests and
  remains subject to later capability checks and strict framing.

`sloosh daemon stop` intentionally connects without client-side socket-peer
eUID or executable-path authentication or `Hello`, and sends only the
pre-negotiation `Shutdown` request. This recovery path remains usable when the
local `slooshd` file was replaced or removed; `Shutdown` carries no credential
and only reduces authority. During a DMG install, the native macOS installer
sends that same fixed request directly to the private default socket before
installing the app; it never executes the installed bundle. Neither path can
send an ordinary request on that connection. These paths keep an incompatible
running daemon operable during installation or upgrade.

### Upgrade procedure

An installed package does not replace a running daemon. On mismatch, stop the
old daemon, then retry so the client starts a matching one. Stopping loses sessions,
forwards, requests, leases, and other in-memory state. If Linux executable-path
verification rejects an in-place-replaced daemon, confirm and terminate that
same-user daemon process manually. Operational steps belong to the
[installation guide](../getting-started/installation.md#upgrade).

## 2. Control messages

Requests and responses are UTF-8 JSON objects with serde's internal `type` tag,
terminated by one newline byte:

```text
{"type":"Status"}\n
{"type":"Hello","wire_protocol":3}\n
{"type":"ProtocolReady","wire_protocol":3}\n
{"type":"Ok"}\n
{"type":"Error","message":"..."}\n
```

The maximum serialized control message is 1,048,576 bytes, including the final
newline. A receiver also refuses a line whose accumulated bytes exceed that
limit before a newline arrives.

On malformed JSON, an oversized line, or an I/O error, the connection handler
may close without a structured `Error` response. Callers must not assume every
transport or parse failure has an NDJSON reply.

An empty line is treated like no message and ends the daemon's request loop for
that connection. Control writers must emit exactly one JSON object per line.

Except for `Status`, `Hello`, and `Shutdown`, control requests require a
negotiated connection. The unnegotiated guard runs before ordinary request
dispatch, so a rejected request cannot open a session, touch a lease, mutate
the vault, start SFTP, create a forward, or append request-specific audit data.

Except during the raw stream states described below, a negotiated connection is
a sequence of request/response exchanges. There is no request ID and no
multiplexing of independent operations on one connection.

### Host management requests

Protocol 3 makes vault host authentication and routing explicit:

- `ListHosts { master_password }` returns `Hosts { hosts }` sorted by alias.
- Each host summary contains only `alias`, `hostname`, optional `port`, optional
  `user`, non-secret `auth` kind, and typed `route`.
- `HostAuth` is exactly one of `agent`, `password { password }`, or
  `key_file { path }`. The selected method is exclusive for vault profiles.
- `HostRoute` is exactly one of `direct`, `managed_host { alias }`, or
  `proxy_jump { spec }`. Managed-host routes reuse another profile; advanced
  ProxyJump preserves OpenSSH comma-chain syntax.
- `UpdateHost` carries complete desired non-secret metadata, the Master
  Password, and optional replacement `auth`. Omitting `auth` preserves the
  existing method and credential. Alias
  renames are unsupported because aliases are lease and ProxyJump identities.
- Mutations reject empty or control-character metadata, port zero, aliases or
  hostnames over 255 bytes, users over 255 bytes, routes/key paths over 1024
  bytes, missing managed hosts, managed cycles/depth overflow, and a managed
  route that names the host itself. Removing a referenced managed host fails.
- `AddCred`, `ListHosts`, `UpdateHost`, and `RmCred` remain daemon-owned. Human
  CLI commands require a real TTY. The desktop adapter collects secrets through
  the bundled native helper before constructing wire requests; secrets never
  enter Svelte or Tauri command arguments.

## 3. Raw frame format

Only `Put` and `Get` switch the channel into raw-frame mode.

```text
offset  size  meaning
0       4     payload length, unsigned 32-bit big-endian
4       N     payload bytes
```

Rules:

- `0 <= N <= 1,048,576`.
- `N == 0` is the required stream EOF marker and carries no payload.
- `N > 1,048,576` is invalid and closes the operation/connection.
- Transport EOF is an error, not a substitute for the zero-length frame.
- A stream may contain any number of non-empty frames. There is no protocol
  total-size cap.
- Empty files are represented by the zero-length EOF frame with no data frame.
- After raw EOF, framing returns to NDJSON for the final `Transfer` or `Error`.

PTY spool budgets do not apply to raw SFTP. Lease expiry does not stop a stream
after `TransferReady`. Exact resource and timeout guarantees belong to
[`SECURITY.md`](../../SECURITY.md#44-bounded-local-resources).

The same buffered reader handles NDJSON and raw frames. Bytes prefetched while
reading `TransferReady` remain available to the raw-frame reader.

## 4. Common transfer response

Successful completion uses:

```json
{
  "type": "Transfer",
  "host": "box",
  "session": "default",
  "local_path": "/local/label",
  "remote_path": "/remote/file",
  "bytes_transferred": 1234
}
```

`local_path` is a label in the daemon protocol. It is not authority for the
daemon to open a local file. The CLI performed the local filesystem operation.

`bytes_transferred` is the number of payload bytes successfully read/written by
the daemon-side SFTP transfer, represented as `u64` with saturating accounting.

## 5. Put state machine

```text
CLI                                             daemon
 |                                                |
 | open and validate local regular file           |
 |                                                |
 | NDJSON Put ----------------------------------->|
 |                         check host lease once   |
 |                         open/reuse SSH session  |
 |                         open remote SFTP file   |
 |                         CREATE|TRUNCATE|WRITE   |
 |<--------------------------- TransferReady NDJSON|
 |                                                |
 | raw data frame ------------------------------->|
 | raw data frame ------------------------------->| write remote handle
 | ...                                            |
 | raw zero-length EOF -------------------------->|
 |                         shutdown remote handle |
 |<------------------------ Transfer or Error NDJSON
```

The `Put` request contains:

- `host`;
- `local_path`, for audit/display only;
- `remote_path`;
- optional `session`;
- optional `lease_token`.

Behavior:

- Failure before the remote file is ready returns NDJSON `Error` instead of
  `TransferReady`; no raw stream follows.
- `TransferReady` means the start-time lease check passed and the remote handle
  is open. The grant covers this complete in-flight operation; the daemon does
  not reevaluate authorization during the stream.
- If remote writing fails after readiness, the daemon drains
  subsequent frames through the required zero-length EOF, then returns
  `Error`. Draining avoids a duplex deadlock with a sender already streaming.
- Failure while shutting down the remote handle returns `Error` after raw EOF.
- A client disconnect, daemon crash, or remote error can leave
  the remote destination truncated or partially written. Put has no remote
  temp-file commit, checksum, resume, or rollback protocol.
- Retrying starts again with `CREATE|TRUNCATE|WRITE`.

The CLI sends chunks no larger than 1 MiB. File total size is not limited by
the protocol. Lease expiry after `TransferReady` does not stop this transfer;
a later transfer needs a live lease.

## 6. Get state machine

```text
CLI                                             daemon
 |                                                |
 | create temp with 0666 reduced by caller umask   |
 |                                                |
 | NDJSON Get ----------------------------------->|
 |                         check host lease once   |
 |                         open/reuse SSH session  |
 |                         open remote SFTP file   |
 |<--------------------------- TransferReady NDJSON|
 |                                                |
 |<-------------------------------- raw data frame |
 |<-------------------------------- raw data frame | read remote handle
 |<-------------------------------- ...            |
 |<----------------------------- raw zero-length EOF
 |<------------------------ Transfer or Error NDJSON
 |                                                |
 | on Transfer: sync + atomic destination commit  |
 | on Error: remove temp, keep destination         |
```

The `Get` request contains:

- `host`;
- `remote_path`;
- `local_path`, for audit/display only;
- optional `session`;
- optional `lease_token`.

Overwrite policy is not carried on the wire. It is enforced by the CLI that
owns the local destination:

- without `--force`, the CLI refuses an existing destination and commits with
  a hard link that still fails if another process creates the path first;
- with `--force`, the CLI commits by same-directory rename;
- the temp file is synced before commit;
- the CLI requests mode `0666` at `create_new`, so the process umask is applied
  atomically by the kernel and the committed file keeps that effective mode.

Behavior:

- Failure before the remote file is ready returns NDJSON `Error` instead of
  `TransferReady`; no raw stream follows.
- After readiness, the start-time grant covers the complete stream; later lease
  state changes do not alter the remote read loop.
- On a remote read error, the daemon sends raw EOF, then NDJSON `Error`.
- The CLI commits only after raw EOF and a final `Transfer` response. A normal
  error removes the temp file and leaves any existing destination unchanged.
- Abrupt CLI termination can leave an orphan temp file, but it does not expose
  a partially written final destination before atomic commit.
- Get has no checksum or resume protocol; retry starts from byte zero.
- Lease expiry after `TransferReady` does not interrupt this transfer. It blocks
  a later `Get` from starting.

## 7. Transfer interruption and sequencing

A peer must complete negotiation and then remain in the state selected by the
last control message:

```text
UNNEGOTIATED
  | Status -> Status                 (stay UNNEGOTIATED)
  | Hello(3) -> ProtocolReady(3)
  v
CONTROL
  | Put/Get accepted
  v
WAIT_FOR_TRANSFER_READY
  | TransferReady
  v
RAW_STREAM
  | zero-length frame
  v
WAIT_FOR_FINAL_CONTROL
  | Transfer/Error
  v
CONTROL

Shutdown is accepted from UNNEGOTIATED or CONTROL and closes the daemon.
```

Sending NDJSON where a raw frame header is expected, or raw bytes where NDJSON
is expected, desynchronizes the channel and normally causes parse, size, or I/O
failure. There is no recovery marker within a connection. Close it and start a
new request.

The raw EOF marker ends only the byte stream. A transfer is not successful
until the final NDJSON `Transfer` arrives. Conversely, transport EOF before raw
EOF or before the final control response is failure even if all expected file
bytes appear to have arrived.

## 8. Approved-hosts fail-closed exchange

`ApproveLease` includes the exact ordered host list shown to the human:

```json
{
  "type": "ApproveLease",
  "id": "ABCD1234",
  "master_password": "...",
  "approved_hosts": ["target", "jump-a", "jump-b"]
}
```

Approval sequence:

1. Human CLI fetches the pending request description.
2. Human CLI unlocks its local vault cache with the entered master password.
3. Human CLI expands all ProxyJump aliases, displays the full ordered list, and
   requires explicit confirmation.
4. Daemon receives the password and `approved_hosts`, unlocks its own vault
   cache, and independently expands the pending request hosts. The unlock is
   serialized with vault mutations and derives/decrypts from one `VaultFile`
   envelope before publishing cache state.
5. Activation occurs only if the vectors are exactly equal.

Any omission, order difference, vault/config change, invalid ProxyJump route,
or older client that omits `approved_hosts` fails closed. The missing field
defaults to an empty vector for parsing, which cannot match a real non-empty
grant. A mismatch or route-resolution error returns `Error` and leaves an
existing pending request available for a new preview/approval attempt. If an
invalid route is visible before `RequestLease` creates pending state, the
request itself returns `Error` instead.

On a DMG-installed Mac, daemon may satisfy a newly created pending request via
its bundled Touch ID or PIN helper before replying. Success returns the already-valid
`Ok` response for `RequestLease`; failure returns `LeaseRequestPending` exactly
as before. Helper traffic uses anonymous child-process pipes, is not part of
this wire protocol, and never exposes the generated bearer lease token to the
requesting connection. Therefore this optional path does not change protocol 3
message shape or sequencing. PIN and Master Password entry use anonymous helper
pipes and never become Tauri command arguments. Raw PIN never becomes a
protocol field. GUI vault initialization uses the existing `InitVault`
`SecretString` over the verified owner-only Unix socket, preserving the daemon
as vault authority.

The daemon also rejects approval from a process ancestry containing the pending
request's anchor. Wrong-password attempts are limited, and pending requests
expire independently.

## 9. Host-key confirmation after activation

Host-key probing happens in human CLI after activation; it is not a wire
subprotocol. Component flow belongs to
[`architecture.md`](architecture.md#4-approval-proxyjump-and-host-keys) and
security guarantees to [`SECURITY.md`](../../SECURITY.md#47-host-key-bootstrap).
Probe failure does not roll back lease activation or create trust.

## 10. Raw-client limit

Readable control JSON does not make text tools complete clients. Correct peers
must implement identity verification, negotiation, capabilities, mixed framing,
transfer completion, and CLI-owned local-file behavior. Manual raw use is
unsupported; use CLI for operations.
