---
name: sloosh
description: Run remote SSH commands in persistent sessions, transfer files, and manage tunnels without exposing credentials to the Agent.
---

# Sloosh

- Use `sloosh <command> --help` for syntax; `sloosh status` for current state.
  Sessions retain cwd, environment, and background jobs.
- Request all needed hosts together: `sloosh request host-a host-b`.
  Continue on `authorized`; if pending, show the printed approval command and wait.
  Do not poll or repeatedly request approval. Leases are process-bound and expire.
- Run with `sloosh run <host> "command"`. If it returns `running`, use
  `sloosh peek <host>`; do not run the command again.
- `sloosh host add --auth agent` writes only SSH config, without a TTY or vault copy.
  `sloosh init`, `sloosh approve <ID>`, and other host-management commands are human-only.
- Never read or collect passwords, private keys, or lease tokens; never fake a TTY
  or automate secure prompts. Missing setup or credentials requires the user.
- For explicit TOFU, use `sloosh request --trust-new-host <host>` (includes jumps).
  Changed keys still require human verification via `sloosh host trust <alias>` or desktop Hosts.
- Do not bypass vault locks, change authentication, or remove ProxyJump routes to
  evade authorization. Dangerous Bypass Mode requires explicit user opt-in;
  when already enabled, no lease is needed. Credential and changed-key errors still apply.
- `put` overwrites remote files; `get --force` overwrites local files.
  Remote `forward -R` may expose a listener. Use either only when intended.
