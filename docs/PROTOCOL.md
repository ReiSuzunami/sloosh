# Local Wire Protocol

This document specifies the current CLI-to-daemon wire contract. The exact
version constant is `WIRE_PROTOCOL_VERSION = 2` in `src/proto.rs`.

Protocol 2 is local IPC over a Unix domain socket. It combines NDJSON control
messages with bounded binary frames for SFTP data. It is not a network API and
has no compatibility promise for arbitrary raw clients.

## 1. Version rule

Wire compatibility is exact, independent of package version. Any incompatible
message shape, tag, default, or sequencing change must bump the wire protocol
version.

For ordinary new CLI connections:

1. CLI authenticates the daemon peer by eUID and canonical executable path.
2. CLI sends `{"type":"Status"}\n` as the first request.
3. Daemon returns a `Status` response containing `wire_protocol`.
4. CLI requires an exact value of `2`.
5. CLI sends `{"type":"Hello","wire_protocol":2}\n`.
6. Daemon replies
   `{"type":"ProtocolReady","wire_protocol":2}\n` and marks that connection
   negotiated.
7. Only then may the CLI send an ordinary request on that connection.

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

`sloosh daemon stop` intentionally connects without `Hello` and sends the
pre-negotiation `Shutdown` request. This keeps an incompatible running daemon
operable during upgrade.

### Upgrade procedure

Installing a new binary does not replace a daemon already running in memory. If
the new CLI reports a protocol mismatch:

1. Finish or abandon any work that depends on active PTY sessions or forwards.
2. Run `sloosh daemon stop` manually.
3. Retry the desired command; the new CLI will auto-start a matching daemon.

Stopping the daemon terminates active sessions and forwards and loses pending
requests, active leases, and other in-memory state. It does not preserve or
migrate live protocol state.

## 2. Control messages

Requests and responses are UTF-8 JSON objects with serde's internal `type` tag,
terminated by one newline byte:

```text
{"type":"Status"}\n
{"type":"Hello","wire_protocol":2}\n
{"type":"ProtocolReady","wire_protocol":2}\n
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

The PTY output spool budgets (64 MiB/run, 64 MiB/session, 1 GiB/root) do not
apply to this raw SFTP stream. Lease duration also does not impose a byte or
duration limit after `TransferReady`. The daemon replaces the SFTP library's
default 10-second request deadline with the pinned Tokio far-future timer
(roughly 30 years), which is operationally unbounded for NAS work.

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
the protocol. If the 2-hour idle or 8-hour absolute lease boundary passes after
`TransferReady`, this transfer continues; a later transfer needs a live lease.

## 6. Get state machine

```text
CLI                                             daemon
 |                                                |
 | create 0600 temp in destination directory      |
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
- the temp file is synced before commit.

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
  | Hello(2) -> ProtocolReady(2)
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

Any omission, order difference, vault/config change, or older client that omits
`approved_hosts` fails closed. The missing field defaults to an empty vector for
parsing, which cannot match a real non-empty grant. A mismatch returns `Error`
and leaves the pending request available for a new preview/approval attempt.

The daemon also rejects approval from a process ancestry containing the pending
request's anchor. Wrong-password attempts are limited, and pending requests
expire independently.

## 9. Host-key confirmation after activation

Host-key probing is not a raw wire subprotocol. It runs in the human CLI after
lease activation while that process still has its temporary vault cache.

The CLI builds dependency-first work:

1. Probe and confirm the first jump directly.
2. Probe later jumps through already trusted/authenticated earlier jumps.
3. Probe the final target through the same resolved ProxyJump route.

Intermediate hops use normal strict known-host verification and normal
authentication. Only the final unknown endpoint accepts a key in a capture
handler, and that connection stops after key exchange without authenticating to
the target. The CLI records the key only after human confirmation.

Failure to probe or refusal to trust does not roll back the active lease, but it
does not create trust either. A later real SSH connection still rejects an
unknown or mismatched key.

## 10. Debugging limits

Control JSON can be inspected with ordinary text tools. That does not make
`nc -U` a complete client. A correct client must also implement:

- daemon peer identity verification;
- exact `Status`/`Hello`/`ProtocolReady` gate;
- request capability rules;
- mixed NDJSON/raw state transitions;
- raw frame size and EOF rules;
- final transfer response handling;
- local temp-file and atomic-commit behavior.

Manual raw protocol use is unsupported and can stop the daemon or mutate local
state when the caller satisfies the relevant request preconditions. Use the CLI
for operational access.
