# Chat MCP requirements

> Non-canonical planning record. It does not define shipped behavior.
> Shipped authority stays in [`SECURITY.md`](../../SECURITY.md),
> [`architecture.md`](../internals/architecture.md), and
> [`protocol.md`](../internals/protocol.md).
> Chinese translation: [`chat-mcp-requirements.zh-CN.md`](chat-mcp-requirements.zh-CN.md).
> Related research: [`cloud-mcp-ssh-research.md`](cloud-mcp-ssh-research.md).

Status: draft requirements agreed in product discussion (2026-08-19).
Implementation must land contract, tests, help, translations, and Skill in the
same change as code. Wire protocol stays at version 3 unless a concrete
incompatible schema, framing, default, or sequencing change appears.

## 1. Problem

ChatGPT and Claude Chat cannot spawn a local `stdio` MCP process. Their
connectors call a remote Streamable HTTP endpoint from vendor cloud.

The market default — a public `/mcp` URL whose gateway holds SSH keys or
passwords — moves host authority off the machine. That contradicts sloosh:
daemon authority, PID-plus-start-time leases, out-of-band approval that cannot
come from the requesting process tree, and no vault password, SSH secret, or
lease token leaving the machine.

Chat users also have no local TTY. Per-command `sloosh approve` is not a
viable Chat UX.

## 2. Outcome

A human installs sloosh on the machine they want Chat to operate. After an
explicit local enable, Chat can use that machine without further prompts. The
same enable may add named remote hosts that already qualify for today's
system-agent-only automatic lease. On those targets, Chat runs authorized
tools unsupervised (YOLO). The cloud never becomes the SSH client or the vault
holder.

## 3. Non-goals

- Exposing `slooshd` as a public Streamable HTTP MCP server.
- A hosted SSH gateway that stores keys, passwords, or `SLOOSH_LEASE`.
- Treating MCP OAuth or an MCP session id as a host lease.
- Per-command or in-chat approval after a host is enabled.
- Auto-enrolling password, key-file, custom-agent, or `IdentityFile` hosts.
- Auto-trusting unknown or changed host keys from Chat.
- Including remote forwards (`-R`) in default YOLO.
- Giving desktop Cursor / Claude Code / Codex a new local-exec API. Those
  clients already have a local shell; they keep using CLI plus Skill.
- Claiming Anthropic MCP Tunnels as a claude.ai connector path. Console tunnels
  are not available as Claude Chat connectors.

## 4. Actors

| Actor | Where | May | Must not |
|---|---|---|---|
| Human | The install machine | Enable Chat, pick allowlist, start/stop bridge, revoke | Paste vault password, keys, or lease tokens into Chat |
| ChatGPT / Claude cloud | Vendor | Act as MCP client, call the relay | See vault, keys, `SLOOSH_LEASE`, or the daemon socket |
| Relay / tunnel edge | Vendor tunnel or operator-owned outbound hub | Bind Chat user ↔ bridge instance, forward MCP frames | Decrypt vault, open SSH, mint or hold host leases |
| `sloosh-bridge` | Same UID as the human on the install machine | Dial out; translate typed MCP tools to protocol 3 | Approve leases, open caller-supplied local paths |
| `slooshd` | Install machine | Authority: Chat grants, SSH, PTY, remote SFTP handles | Listen on public 443 |

OAuth proves only that this Chat account is bound to this bridge. Host
capability stays a daemon grant.

## 5. Architecture

```text
Chat  -- MCP + OAuth -->  relay  -- existing outbound tunnel -->  bridge
                                                                  |
                                                                  | Unix socket
                                                                  | Status → Hello → ProtocolReady
                                                                  v
                                                               slooshd
                                                                  |
                                              +-------------------+-------------------+
                                              |                                       |
                                              v                                       v
                                    local (no SSH)                    allowlisted SSH hosts
```

Rules:

- Chat never dials `slooshd`. The install machine only makes outbound
  connections.
- Protocol 3 stays local IPC. The bridge is a new client of the existing
  daemon, not a new wire version.
- The adapter must not change authorization order, transfer caps, or atomic
  download semantics.
- `integration-test-hooks` stays test-only and never appears in CLI or MCP.

## 6. First-class targets

### 6.1 `local` (first Chat use)

The primary Chat target is the machine that runs sloosh, not a remote SSH
host.

- Stable identity: `local` (or the machine's documented hostname alias).
- Execution: a persistent user-UID shell owned by the daemon. Session, cwd,
  environment, and background jobs survive across Chat turns, matching today's
  remote session model.
- No sshd, host key, or ssh-agent is required for `local`.
- Enabling Chat for this daemon is the entire user-auth gate for `local`.
- `local` is Chat-audience only. Ordinary CLI and desktop clients do not gain
  a generic local-exec API through this feature.

### 6.2 Remote SSH (second use)

Optional named aliases from the existing host inventory.

A remote host may enter the Chat allowlist only when all of the following
hold, and they are rechecked on every grant use:

- the exact target and every ProxyJump hop use default `$SSH_AUTH_SOCK` or a
  vault `Agent` profile;
- no `IdentityFile`, custom `IdentityAgent`, password, or key-file method;
- every hop already has a trusted key in `~/.sloosh/known_hosts`;
- daemon can authoritatively inspect the scope (unlocked vault or proven
  OpenSSH-config agent-only path).

A cold encrypted CLI-only vault still cannot treat "unreadable" as
"agent-only". Chat then refuses that host rather than pending a TTY approve.

If a host later leaves this policy, Chat access fails closed immediately.

## 7. Enable is the only Chat user authentication

Chat has no approval surface. There is no `sloosh approve` in the conversation
and no password field in Chat.

One local, explicit action turns Chat on, for example `sloosh chat enable`
and/or a desktop control. That action:

- starts or requires the outbound bridge;
- always offers `local`;
- may add a named system-agent-only allowlist;
- records audience `chat` on the daemon.

After enable, Chat does not ask the human again for user authentication on
those targets. Changing the allowlist, disabling Chat, or stopping the bridge
is another local explicit action.

Desktop-agent leases are unchanged. Password, key-file, and custom-agent
scopes still need today's out-of-band human approval on CLI/desktop paths.

## 8. YOLO

YOLO names the existing lease rule for the Chat audience: a host grant is
capability, not command intent. The daemon does not inspect shell safety.

Once Chat is enabled for a target and a Chat grant is live:

- `run` / `peek` / `send` / `interrupt` / session open-kill on that target
  execute without further prompts;
- SFTP on that target follows the current start-time lease and atomic-`get`
  rules;
- loopback-only local forwards (`-L`) may be included as typed tools.

YOLO does **not** include:

| Action | Why |
|---|---|
| A host outside the allowlist | New host capability |
| Password, key-file, custom-agent, `IdentityFile` | Broader credential authority |
| Unknown or changed host keys | Trust, not user auth; Chat cannot confirm fingerprints |
| Remote forward (`-R`) | Deliberate extra exposure |
| Stretching idle to forever | YOLO means "do not ask per command", not "never revoke" |
| Letting Chat expand its own allowlist | Enable stays human-local |

Idle uses the existing shared vault timeout (1 / 5 / 15 / 30 minutes) and the
daemon's 8-hour hard cap. Activity may refresh the idle clock the same way
current grant checks do. Expiry makes the target inaccessible until Chat is
still enabled and a new automatic grant can be issued; it does not pop a Chat
approval dialog.

PTY lifetime on expiry follows today's rule: the session may remain but is
unusable until a live grant exists. In-flight SFTP past `TransferReady` may
finish; new operations fail.

## 9. Typed Chat tools

MCP exposes compiled tools, not raw protocol 3 and not `sloosh` argv.

Minimum set:

| Tool | Target | Notes |
|---|---|---|
| `run` | `local` or allowlisted host | Persistent session; bounded reply + spool |
| `peek` | same | Incremental output |
| `interrupt` / `kill` | same | Reduce access |
| `sftp_get` / `sftp_put` | same | CLI/bridge opens local paths; daemon treats `local_path` as a label; `get` uses same-directory `create_new` and atomic commit |
| `forward_local` | allowlisted SSH host | Loopback bind only |

Do not expose: arbitrary daemon messages, `-R`, host inventory mutation, vault
unlock, `host trust`, or Skill install.

PTY ring, reply, spool, session, and root budgets stay exactly as
`SECURITY.md` specifies.

## 10. Flows

### 10.1 One-time setup

1. Human installs sloosh and runs `sloosh init` on the machine Chat should
   control.
2. Human enables Chat and optionally names remote agent-only hosts.
3. Daemon records audience `chat`. `local` is eligible. Remote names are
   admitted only if they still match §6.2.
4. Bridge authenticates the daemon (eUID + canonical `slooshd` path),
   completes `Status → Hello → ProtocolReady`, and dials the relay outbound.
5. Human adds the connector in ChatGPT and/or Claude (relay URL or official
   tunnel identity) and finishes vendor OAuth.
6. Relay stores Chat user U ↔ bridge instance B. No host lease exists yet
   beyond enable.

### 10.2 Daily command

1. Chat `tools/call` `run` on `local` or an allowlisted host.
2. Relay accepts only a valid OAuth binding to B and forwards the frame.
3. Bridge asks the daemon for a Chat grant on that exact scope.
4. Daemon auto-issues a method-restricted grant when policy still holds;
   otherwise it returns a typed refusal to Chat (not a pending TTY approve).
5. Bridge issues the existing `Run` (or equivalent) request.
6. Bounded output returns to Chat. Secrets are not logged.

### 10.3 Revocation (both layers required)

| Human action | Effect |
|---|---|
| Disconnect Chat OAuth / remove connector | Relay stops forwarding; local grant may still exist |
| Disable Chat / remove host from allowlist / Chat grant idle | Daemon refuses `Run`; OAuth may still be valid |
| Stop bridge or drop outbound | Chat cannot invoke tools |
| `sloosh daemon stop` | Sessions, forwards, and grants die, as today |

Chat OAuth expiry is not host-grant expiry. Both must be live.

## 11. Relay choice (open)

The local grant model is the same. Only how Chat finds the bridge differs.

| Option | ChatGPT | Claude Chat | Notes |
|---|---|---|---|
| A. OpenAI Secure MCP Tunnel | Official outbound path | No | ChatGPT-only unless a second path exists |
| B. Operator-owned outbound hub with public `/mcp` | Connector URL | Connector URL | Needed for both Chats; hub still holds no vault |
| C. A + B | Both | Both | Same bridge, two edges |

Anthropic MCP Tunnels remain out of the Chat connector path until the vendor
exposes them there.

Pick A or B before implementation. Do not block `local` + YOLO on that pick.

## 12. Security invariants (must not move)

- Daemon remains authority. Chat grant is a new audience, not a replacement
  for PID-plus-start-time or `SLOOSH_LEASE` on CLI/desktop.
- Lease tokens never return to Chat, the relay, or vendor cloud.
- Vault passwords, SSH passwords, private keys, interactive `send` contents,
  and decrypted vault data are never passed or logged.
- Human approval, when still required on CLI/desktop, cannot come from the
  requesting process tree. Chat enable is a separate human-local control, not
  an in-band model approval.
- Host-key mismatch fails closed. Chat is not a trust UI.
- Local forwarding binds loopback only.
- CLI/bridge alone opens SFTP local paths.
- Resource bounds stay as documented in `SECURITY.md`.
- Automatic grants stay method-restricted and fail closed if authentication
  changes underfoot.

New Chat threat: prompt injection or a stolen Chat OAuth token yields a user-UID
shell on the install machine (`local`) and YOLO on allowlisted SSH hosts. Same-UID
local malware is already outside the strong boundary; the new caller sits in
vendor cloud. Enable must therefore be explicit, off by default, and reversible
without a Chat round-trip.

## 13. Acceptance

Must pass:

1. With Chat disabled, vendor cloud cannot run anything on the machine.
2. After enable with no remote allowlist, Chat can `run`/`peek` on `local`
   only, with session persistence across turns.
3. A system-agent-only, known-key host named at enable is YOLO for Chat.
4. Password, key-file, custom-agent, `IdentityFile`, and unknown-key hosts are
   refused by Chat with a typed error and no pending approve.
5. Changing a host off agent-only or changing its host key revokes Chat access
   immediately.
6. `slooshd` has no public listener. Capture of relay traffic shows no vault
   material and no lease token.
7. Protocol 3 remains 3; mismatch/upgrade tests still hold.
8. Desktop/CLI key-file and password hosts still require today's approval.
9. Default YOLO rejects `-R`.
10. Disconnect OAuth or disable Chat independently stops new operations.
11. PTY/reply/spool bounds still apply to Chat-originated runs.
12. `get` still uses same-directory `create_new` and atomic commit; daemon
    still does not open caller-supplied local paths.

## 14. Documentation owners when this ships

| Owner | Update |
|---|---|
| README + `--help` + translations | Chat enable, `local`, YOLO scope |
| `SECURITY.md` | Chat audience, `local` exec, cloud-caller threat |
| `architecture.md` | Bridge, relay, `local` vs SSH |
| `protocol.md` | Only if messages or sequencing change (then bump) |
| `SKILL.md` | Chat is not the desktop Agent path |
| `cloud-mcp-ssh-research.md` | Point at this requirements record |

Do not copy exact numeric limits into user manuals.
