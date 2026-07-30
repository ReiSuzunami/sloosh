---
name: sloosh
description: Use when a task needs to run commands on a remote server/VPS over SSH — deploying, checking logs, restarting services, editing files remotely — especially when the work spans multiple calls and needs a persistent shell (cwd/env/background jobs must survive between commands), or when the agent must never see SSH passwords/keys and instead needs a human to approve host access out of band.
---

# sloosh

`sloosh` runs commands on remote hosts over SSH from a long-lived background
daemon. It fixes two things plain `ssh`/subprocess calls don't: your shell
state (cwd, env vars, background jobs) survives across calls, and you never
touch a password or key — a human approves access to each host out of band.

## Bootstrap

Before the first SSH task, check whether the binary is available:

```sh
command -v sloosh && sloosh --version
```

If it is missing or too old to provide `sloosh init` and `sloosh skill`, explain
the official command-line package for the user's OS and ask before installing
anything. Prefer the verified GitHub Release archive or Homebrew path described
in the repository's installation guide. That package includes the managed
`slooshd`; never start it directly. The macOS DMG is an optional desktop
control plane and does not install the CLI. Do not use `curl | sh`, request
credentials, bypass Gatekeeper/SmartScreen, or silently invoke a package
manager.

Once the CLI is available, explain the matching human-approval setup:

- `sloosh init` is a human-only terminal flow and command-line-only installs
  use the separate-terminal approval fallback: the human runs the printed
  `sloosh approve <ID>` command in another terminal.
- On macOS with the desktop app, the human uses its Setup and Security screens
  for login Keychain and the possible `Sloosh Approval` prompt. Native lease
  approval lets the human choose Touch ID, PIN, or Master Password before the
  secure authentication step.
  The CLI and app then share the app's private daemon. The user handles every
  native prompt; `Always Allow` avoids repeated Keychain prompts, while `Allow`
  grants one-time access.

Then ask the user to run `sloosh init` themselves in their own terminal, stop,
and wait. Never run it for them, fake a TTY, or enter a vault password. After
they confirm completion, you may run `sloosh skill status` and `sloosh status`
to verify Skill and daemon state. If they want native approval, ask them to
open the desktop app and complete its setup themselves; do not automate its
secure prompts.

## Mental model

A `sloosh` session is a persistent remote shell, not a one-shot command —
`cd` and `export` in one call are still in effect on the next. Every
host-touching command needs a **lease**: a human must approve access to that
host before you can use it. When you're unsure what's going on (is there a
session already? is a host authorized?), run `sloosh status` first instead
of guessing.

## Key commands

```
sloosh request myhost                       # ask a human to authorize myhost
sloosh host trust myhost                    # human-only: inspect/add/replace a host key
sloosh run myhost "npm test"                 # run a command in myhost's default session
sloosh peek myhost                           # incremental output since your last peek
sloosh put myhost ./build.tar.gz /srv/app/   # upload a local file over the same connection
sloosh get myhost /var/log/app.log ./log.txt # download a remote file
sloosh forward myhost -L 8080:127.0.0.1:80  # loopback-only local tunnel
sloosh forward myhost -R 9000:127.0.0.1:3000 # remote listener to a local service
sloosh skill status                          # Agent Skill install/update state
sloosh status                                # daemon/lease/session overview — run this when lost
```

## Fixed behavior rules

- After `sloosh request <host>`, continue when it prints `authorized`. On a
  pending fallback, show the printed approval command to your user and **stop
  and wait** — do not poll in a loop or re-request. On DMG-installed macOS,
  Touch ID, an approval PIN, or the Master Password may complete the request
  without another terminal.
- If `request` reports an invalid ProxyJump cycle or depth, show that error to
  the user and stop. Never retry with a subset of hosts or bypass the route.
- Active leases idle out according to the human's shared vault timeout
  (1, 5, 15, or 30 minutes; default 15). Do not assume a prior lease remains
  active; use `sloosh status` and request approval again when needed.
- If `run` returns `running` (it hit its timeout but the command is still
  going), use `sloosh peek <host>` to follow up incrementally — do not
  re-run the command.
- **Never ask the user for a password or key.** Host management
  (`sloosh host add/edit/trust/rm/list/show`) is something the user does themselves, interactively, in
  their own terminal. If a host isn't set up yet, tell them to run
  `sloosh host add` and wait. Humans may choose SSH agent, password, or an
  unencrypted Ed25519/ECDSA key-file profile plus direct, managed-host, or
  ProxyJump routing. RSA and encrypted private keys must be loaded into
  ssh-agent.
- `sloosh init`, `sloosh approve`, and every `sloosh host` command are human-only.
  Never work around their TTY checks. The Agent Skill cannot approve leases,
  initialize the vault, or grant itself new authority.
- If an operation reports an unknown or changed host key, ask the user to open
  Hosts in the desktop app or run `sloosh host trust <alias>` themselves, then
  stop and wait. The user must compare the shown new fingerprint with an
  independent source and choose Add/Replace/Recheck/Cancel. Never invoke the
  trust command, edit either known_hosts file, or auto-accept a changed key.
- Sessions keep their working directory and environment between calls; you
  don't need to `cd` back into place or re-`export` things every time.
- `put` truncates an existing remote destination; check the path first. A
  transfer authorized before lease expiry may finish, but new operations fail.
- `get` refuses to overwrite an existing local file. Use `--force` only when
  replacing that file is explicitly intended; completed downloads are
  committed atomically.
- Port forwarding supports loopback-only `-L` and remote `-R`. Use `-R` only
  when a remote listener is intended, and choose its bind address carefully:
  the SSH server's `GatewayPorts` policy decides whether it is externally
  reachable. Non-loopback local `-L` listeners are rejected.

## More detail

Every subcommand explains itself: run `sloosh <command> --help`. Error
messages are self-teaching too — e.g. a missing lease tells you exactly
which command to run and what to show your user. This document intentionally
does not duplicate the flag reference.
