# sloosh

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

For the full design (architecture, wire protocol, session/output model,
audit log), see [DESIGN.md](./DESIGN.md).
