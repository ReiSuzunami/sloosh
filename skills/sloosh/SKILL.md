---
name: sloosh
description: Use when a task needs to run commands on a remote server/VPS over SSH — deploying, checking logs, restarting services, editing files remotely — especially when the work spans multiple calls and needs a persistent shell (cwd/env/background jobs must survive between commands), or when the agent must never see SSH passwords/keys and instead needs a human to approve host access out of band.
---

# sloosh

`sloosh` runs commands on remote hosts over SSH from a long-lived background
daemon. It fixes two things plain `ssh`/subprocess calls don't: your shell
state (cwd, env vars, background jobs) survives across calls, and you never
touch a password or key — a human approves access to each host out of band.

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
sloosh run myhost "npm test"                 # run a command in myhost's default session
sloosh peek myhost                           # incremental output since your last peek
sloosh put myhost ./build.tar.gz /srv/app/   # upload a local file over the same connection
sloosh get myhost /var/log/app.log ./log.txt # download a remote file
sloosh forward myhost -L 8080:127.0.0.1:80  # loopback-only local tunnel
sloosh forward myhost -R 9000:127.0.0.1:3000 # remote listener to a local service
sloosh status                                # daemon/lease/session overview — run this when lost
```

## Fixed behavior rules

- After `sloosh request <host>`, show the printed approval command to your
  user and **stop and wait** — do not poll in a loop or re-request.
- If `run` returns `running` (it hit its timeout but the command is still
  going), use `sloosh peek <host>` to follow up incrementally — do not
  re-run the command.
- **Never ask the user for a password or key.** Credential enrollment
  (`sloosh add`) is something the user does themselves, interactively, in
  their own terminal. If a host isn't set up yet, tell them to run
  `sloosh add` and wait.
- Sessions keep their working directory and environment between calls; you
  don't need to `cd` back into place or re-`export` things every time.
- `put`/`get` stream files in frames of at most 1 MiB with no total-size cap.
  Command-output spool limits do not apply to SFTP, and the dependency's short
  request timeout is raised to a far-future deadline. `put` truncates an
  existing remote destination; check the remote path before starting it.
- A file transfer is lease-authorized before streaming starts. Once started,
  that finite transfer may finish even if the lease expires; lease expiry
  still blocks new operations.
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
