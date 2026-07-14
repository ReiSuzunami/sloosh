# Security

This document defines the current threat model and capability boundaries. It
describes implemented controls, not a claim that a same-user daemon can isolate
hostile code running under that user account.

## 1. Assets

Sloosh handles these security-sensitive assets:

- the vault master password and SSH passwords;
- decrypted vault entries and the derived vault key while leases are active;
- active lease host scopes and `SLOOSH_LEASE` bearer tokens;
- authenticated SSH connections, persistent PTY sessions, and port forwards;
- local upload/download contents and remote SFTP contents;
- trusted SSH host keys;
- local state under `~/.sloosh`, including vault, socket, daemon log, audit log,
  known_hosts, and spool output.

Command text and spool output can contain application secrets even when sloosh
credentials are correctly protected. Do not place secrets in command arguments
unless they may also appear in audit/spool state.

## 2. Trust assumptions

Sloosh assumes:

- the kernel correctly reports Unix socket peer credentials;
- the OS user account, installed binary path, and human approval terminal are
  not already fully compromised;
- the human checks the exact host list and verifies new host-key fingerprints
  against an independent source when needed;
- remote SSH servers and their filesystems may fail or behave maliciously, but
  cannot bypass local UDS permissions without a separate local compromise.

Root, an administrator, a kernel compromise, a debugger with access to sloosh
process memory, or full compromise of the current OS user is outside the strong
protection boundary.

## 3. Adversaries considered

The design reduces risk from:

- another unprivileged OS user trying to connect to the local daemon or read
  state files;
- a prompt-injected agent trying to approve its own request from the same
  process tree;
- a stale or malicious socket endpoint impersonating the daemon at a different
  executable path;
- an agent asking the daemon to open an arbitrary local path during SFTP;
- unbounded single-message, single-frame, or per-session spool allocation;
- accidental exposure of a local forward beyond loopback, or an unintended
  remote listener;
- approval-time ProxyJump scope changing between human preview and daemon
  activation.

The design does not fully isolate a malicious process already running as the
same UID. See Section 8.

## 4. Implemented guarantees

### 4.1 Daemon identity from the CLI

Every verified `UnixChannel::connect` checks both:

- socket peer eUID equals the CLI effective UID; and
- socket peer executable canonical path equals the current `sloosh`
  executable canonical path.

The CLI refuses a peer that fails either check. Ordinary commands then send
`Status`, require the exact wire protocol version, send `Hello` for that
version, and require matching `ProtocolReady` before sending the business
request. The daemon independently keeps a negotiated flag per connection.
Before `Hello` succeeds it permits only `Status`, `Hello`, and `Shutdown`;
ordinary requests fail before request-specific side effects.

This prevents simple socket squatting by a different executable. It is a path
and process check, not code signing or inode pinning.

### 4.2 Client identity and host authorization in the daemon

The daemon gets the peer PID from `SO_PEERCRED` on Linux or `LOCAL_PEERPID` on
macOS. It never accepts a caller-supplied PID as identity.

An active lease is anchored to a PID plus process start time. The daemon keeps
the kernel-provided subsecond resolution: Linux clock ticks and macOS `timeval`
microseconds are not truncated to whole seconds. A later caller is authorized
only when:

- its current ancestry contains that exact anchor process instance; or
- it presents the active lease's `SLOOSH_LEASE` token;

and the lease includes the requested host alias.

Vault-backed ProxyJump aliases need their own host coverage. Lease approval
compares the human CLI's expanded `approved_hosts` list with an independent
daemon-side expansion after unlock. A missing, reordered, stale, or changed
list fails closed.

Long-lived forwards store an opaque `LeaseGrant` scoped to one host and active
lease. They do not retain a short-lived creator CLI PID. Real traffic refreshes
the lease; background validation does not.

Remote routes have a monotonic `Pending -> Active -> Closed` gate. A server-
initiated channel can dial the local target only while the route is `Active`.
The local connect is bounded to 10 seconds and races closure; authorization is
checked again before accept. Stop and expiry close the route before awaiting a
remote cancellation reply, bound that reply to 2 seconds, then drop the SSH
connection regardless.

### 4.3 Local file authority

For SFTP, the CLI alone opens local paths:

- `put`: CLI opens a local regular file and sends its bytes over raw frames;
- `get`: CLI creates a temp file in the destination directory with requested
  mode `0666`, allowing the caller's umask to determine its effective mode,
  and commits it only after a successful final daemon response.

The daemon receives `local_path` only as an audit/display label. It owns the
remote SFTP handle but never opens that local path. This removes the prior
confused-deputy surface where a raw client could ask the daemon to read or
overwrite an arbitrary local file.

`get` refuses overwrite by default. `--force` uses same-directory rename.
Normal transfer failures leave an existing destination unchanged.

The daemon checks the host lease before opening the remote SFTP handle and
sending `TransferReady`. That start-time grant covers the complete in-flight
operation; authorization is not reevaluated during the stream. Idle or absolute
lease expiry blocks a new transfer but does not abort one already ready. This
avoids turning lease lifetime into a NAS file-size or transfer-duration limit.
The daemon replaces `russh-sftp`'s default 10-second per-request timeout with
the pinned Tokio release's far-future timer (roughly 30 years). This is
operationally unbounded, not mathematical infinity, and intentionally trades
bounded wait time for correctness on slow storage. SSH/server/network failure
or explicit daemon/process termination remains the termination path.

### 4.4 Bounded local resources

- NDJSON control message: at most 1 MiB including newline.
- Raw transfer frame: at most 1 MiB. Total transfer size has no application
  cap because a stream may contain any number of frames.
- Session ring: 256 KiB.
- Spool file: 64 MiB per run, then an explicit truncation marker.
- Spool retention: 64 MiB budget per session directory, oldest first,
  best-effort.
- Spool root: 1 GiB hard application budget across every host/session, charged
  by bytes actually persisted.
- Active spool: active paths are protected but reserve no unused capacity.
  One lazy root index seeds an incremental ledger; later run start/end paths do
  not rescan the full tree. Cleanup deletes oldest inactive files when actual
  output needs room. Delete failure is logged and may stop persistence at the
  cap, but is not propagated as a command failure and never deletes active
  files.
- An incomplete initial index pauses new persistence and retries after a
  backoff instead of granting against unknown bytes. Run files use
  collision-safe `create_new`, so reused sequence numbers cannot truncate
  retained history.
- ProxyJump recursion: at most 8 hops, with cycle rejection.

Spool limits cover PTY command output only. They never cap SFTP bytes or
duration. Other resources still have no global process, connection-count,
host-count, audit-log, daemon-log, or user-selected SFTP disk quota.

### 4.5 Filesystem permissions and path handling

Sloosh-owned private directories are created or repaired to `0700`.
`ensure_private_dir` rejects symlinks, non-directories, and wrong ownership,
then opens with `O_DIRECTORY | O_NOFOLLOW`. On macOS it clears extended ACLs
before applying mode `0700`.

A non-default `$SLOOSH_SOCKET` parent is not owned by sloosh and is never
repaired. It must already be a current-eUID-owned mode-`0700` directory; on
macOS it must also have no extended ACL. Otherwise bind fails without changing
its mode or ACL.

Specific files use these controls:

- daemon socket: `0600` inside a private directory;
- daemon log and audit log: opened `0600` with `O_NOFOLLOW`; macOS extended
  ACLs are cleared;
- spool files: encoded single-component host/session directories,
  collision-safe `create_new`, `0600`, and `O_NOFOLLOW`;
- vault: random `create_new` temp file at `0600`, then atomic rename inside the
  private state directory;
- sloosh known_hosts: set to `0600` after recording;
- local download temp: random `create_new` file requested at `0666`, reduced by
  the caller's umask in the destination directory, then atomic commit.

These controls protect against other users and common symlink/path mistakes.
They do not stop the owner UID from modifying its own files.

### 4.6 Secret and log handling

The vault uses Argon2id and ChaCha20-Poly1305. A fresh salt and nonce are used
for each save. Successful AEAD decryption is the password check.

Vault mutations and `unlock_for_lease` share one async mutation lock across disk
read-modify-write and cache publication. Unlock reads one `VaultFile` envelope,
derives the key from that envelope's KDF parameters, decrypts that same
envelope's nonce/ciphertext, then publishes the cache as one unit. This prevents
mixed disk snapshots and an older unlock/cache refresh overwriting a newer
mutation. The daemon cache is cleared and zeroized after the last active lease
expires. Approval creates a separate temporary cache in the human CLI, which is
cleared after preview and host-key confirmation.

`SecretString` redacts `Debug` and zeroizes on drop. The daemon logs request
type, not complete request fields. Audit does not record credentials or command
output, but it does record command text and transfer paths.

Audit writes are best-effort. Audit is operational evidence, not an
append-only, remote, signed, or tamper-resistant security control.

### 4.7 Host-key bootstrap

Approval orders host-key confirmation by dependency: jump hosts first, then
targets. A target reachable through ProxyJump is probed through that route.
Intermediate hops use strict known-host verification and normal authentication.
Only the final unknown target uses a temporary key-capture handler, and the
probe stops before authenticating to that target.

No key is recorded without human confirmation. Probe failure or rejection
leaves the host unknown, and real SSH connection attempts remain fail closed.

## 5. Request capability boundary

The daemon, not the CLI, is the authority for host operations. Current request
classes are below. Except for `Status`, `Hello`, and `Shutdown`, every wire
request first requires a negotiated protocol 1 connection; the table lists
additional authority after that gate.

| Request or command | Required authority | Notes |
|---|---|---|
| `Run`, `Peek`, `Send`, `Interrupt` | active lease for host | PTY access |
| `Open`, `Kill` | active lease for host | create/reuse or terminate session |
| `Put`, `Get` | negotiated connection plus active lease at start | after `TransferReady`, current stream completes under the start-time grant |
| `Forward -L` | active lease for host | loopback listener only; stable grant retained |
| `Forward -R` | active lease for host | remote listener; stable grant retained; exposure follows sshd policy |
| `Status` | no handshake or lease | protocol/version and read-only state disclosure |
| `Hello` | exact protocol version | opens per-connection gate; wrong version leaves it closed |
| `Ls`, `ForwardLs` | negotiated connection, no lease | read-only state disclosure to same UID |
| `ForwardStop` | no lease | only reduces access |
| `Shutdown` / `daemon stop` | no handshake or lease | operational control; same-UID DoS surface |
| `RequestLease` | peer PID, no active lease | creates pending request and anchor |
| `DescribeLeaseRequest` | no active lease | exposes pending request details |
| `ApproveLease` | master password, separate ancestry, exact host list | CLI requires TTY; daemon cannot prove TTY from raw protocol |
| `VaultExists` | no lease | metadata only |
| `InitVault` | no existing vault plus new master password | CLI requires TTY |
| `AddCred` | master password | may create first vault; CLI requires TTY |
| `RmCred` | master password | CLI requires TTY |
| `log` | local file read | no daemon request |

A TTY check is CLI policy, not a server-side protocol credential. A raw same-UID
client can send the underlying vault requests, but still needs the relevant
password and state preconditions.

## 6. Lease and forward timing

- Lease idle limit: 2 hours.
- Lease absolute limit: 8 hours.
- Lease reaper interval: 60 seconds. API use also prunes synchronously.
- Forward grant check interval: 15 seconds without touching idle time.
- Real accepted forward traffic revalidates and touches the lease.
- Remote target connect timeout: 10 seconds.
- Remote listener cancellation timeout: 2 seconds, followed by SSH teardown.
- Session idle limit: 8 hours, checked every 5 minutes.

Lease expiry does not terminate persistent PTY sessions or their remote
processes. It blocks later access. A forward is live network access, so expiry
closes its listener and existing tunnels, with up to the forward reaper interval
of detection delay when no new connection arrives.

An SFTP stream already past `TransferReady` is also allowed to complete. The
8-hour absolute cap applies to starting later operations, not to truncating an
authorized in-flight file transfer.

## 7. Host-key and remote-host limitations

The routed approval probe proves only the key observed through the selected
route. A compromised network path or already-trusted jump host may present a
false target key. The human must compare the SHA256 fingerprint with an
independent source for high-value hosts.

SFTP `put` opens the remote path with create/truncate/write. Interruption can
leave a partial remote file. There is no remote atomic replace, checksum, or
resume protocol. `get` protects the local destination with a temp file and
atomic commit, but an abrupt CLI process kill can leave an orphan temp file.

## 8. Explicit non-guarantees and residual risks

Sloosh does not guarantee protection from hostile same-UID code. Such code may:

- connect as a raw UDS client because the daemon intentionally accepts
  same-user tools and derives authority from peer PID/ancestry, not client
  executable identity; ordinary requests still require a correct protocol 1
  `Hello` first;
- issue pre-handshake `Status` or `Shutdown`, then negotiate and issue unleased
  `Ls`, `ForwardLs`, `ForwardStop`, lease-request, and metadata requests;
- inherit a lease when injected into or launched under the authorized anchor's
  process tree, or use a stolen `SLOOSH_LEASE` token;
- replace or inject into a process at the expected canonical executable path;
- delete, replace, or tamper with owner-writable vault, known_hosts, audit,
  spool, socket, or daemon state;
- exhaust CPU, memory, descriptors, pending requests, sessions, connections,
  audit/daemon logs, or user-selected SFTP storage even though protocol frames
  and PTY spool are bounded;
- read process memory or environment if OS permissions/debug policy already
  permit it.

CLI daemon verification compares eUID and canonical path. It does not verify a
code signature, binary hash, inode identity, launch service identity, or absence
of runtime injection.

Human approval grants host capability, not command intent. Once authorized, an
agent can run arbitrary remote commands, transfer files, and create allowed
local or remote forwards for that host. A remote forward may expose a server-
side listener according to sshd policy. Sloosh does not inspect shell commands
for safety.

Spool append and eviction still use synchronous filesystem calls. A slow or
stalled spool filesystem can delay PTY consumption and other spool writers at
budget pressure, although the ledger avoids per-run full-tree scans and keeps
cleanup errors out of command results.

Audit can be missing, partially written, deleted, or modified by the owner. Do
not use it as the sole control for compliance or incident evidence.

The UDS protocol is not encrypted at the application layer. Confidentiality
relies on local OS isolation and point-to-point socket access.

## 9. Reporting a vulnerability

Prefer a private GitHub Security Advisory through the repository's Security
tab when that feature is enabled. Include affected version/commit, platform,
reproduction steps, impact, and any proposed fix.

If private advisory reporting is unavailable, contact a maintainer privately
using contact information published on the repository or maintainer profile.
Do not open a public issue containing exploitable details before a coordinated
fix is available. Never include real vaults, passwords, lease tokens, private
keys, or sensitive spool/audit contents in a report.
