# Sloosh manual

## Dangerous Bypass Mode

### Credential unlock in bypass mode

After a daemon restart or credential-cache expiry, unlock the desktop Hosts
page or run `sloosh host list` yourself. Successful host add/edit/remove/list
and vault initialization also publish verified credentials to the bypass daemon.
Adding a host works before any lease exists; no second approve/trust is needed.
The idle limit follows the timeout setting; the hard limit is eight hours.
Normal reads do not reset that hard limit. Master Password
is not saved by the daemon. Wrong-password operations never unlock it.

A locked vault cannot tell whether an alias exists: connection and jump
resolution report VaultLocked rather than trying another destination. This
also applies to config-only hosts while an encrypted vault is locked. After
unlock, truly absent profiles still follow SSH config/system Agent normally.
Existing SSH connections keep their original connection; edits affect new
connections, which use coherent address/user/route/auth snapshots.
Locking the desktop management page does not revoke daemon leases or its
bypass cache; stop the daemon if immediate shutdown is required.



Opt in only when you accept all-access authority for same-user clients and the
risk of trusting a first-connection attacker. Use the exact `slooshd` selected
by your CLI (its sibling for command-line installs; on macOS the installed app's
private helper may take precedence). Stop an existing daemon first; stopping
terminates sessions and forwards. Then start that helper in a separate terminal:

```sh
sloosh daemon stop
/path/to/selected/slooshd --dangerous-bypass-mode
```

Keep it running. Use `run`, `put`, `get`, or `forward` directly: no lease request,
host-scope authorization, token, or renewal is needed. `sloosh request myhost`
remains an optional route/vault-readiness check and creates no lease.
No approve popup/terminal confirmation is needed. Unknown target and jump-host keys are saved automatically;
known-key changes still fail. SSH authentication and encrypted-vault unlock
remain required. Credential-cache expiry still requires a human unlock, not
lease renewal. Startup and compatibility requests are visible in `sloosh log`;
first-use trust is warned in daemon output. This is not a per-call flag.

For persistent opt-in, open desktop **Security → Dangerous Bypass Mode →
Enable on next start** and accept the risk confirmation. The GUI saves the
startup policy; it does not interrupt the running daemon. Stop and start the
daemon when ready (all sessions, forwards, and leases are lost on stop).
CLI and desktop auto-spawn honor the saved setting on subsequent starts.

The shared protected configuration is `~/.sloosh/vault-settings.json` (or
`$SLOOSH_HOME/vault-settings.json`). Preserve its timeout and set:

```json
{"version":1,"idle_timeout_minutes":15,"dangerous_bypass_mode":true}
```

Keep the file owner-only (`0600`). Missing file/field defaults off; corrupt or
unsafe settings prevent startup. The flag enables bypass even when the saved
setting is false; it does not change the saved configuration.

To disable, use **Disable on next start** (or set the config field false), then
stop and restart without the flag. Keys already added remain trusted; disabling
is not trust rollback.


English | [简体中文](manual.zh-CN.md)

This manual covers human setup and everyday CLI and desktop use. Agents should
follow the embedded [Agent Skill](../skills/sloosh/SKILL.md). Security
guarantees and limits live in [SECURITY.md](../SECURITY.md).

## Initialize

Run initialization yourself in an interactive terminal:

```sh
sloosh init
```

It installs the embedded Agent Skill and initializes the credential vault.
Command-line-only installations use approval from another human terminal for
password, key-file, and custom-agent scopes. Default system SSH-agent-only
scopes authorize automatically. The macOS desktop app configures Keychain
access, Touch ID, and an optional approval PIN through its own Setup and
Security screens.

Verify the result:

```sh
sloosh skill status --agent auto
sloosh status
```

Installation, checksums, upgrades, and platform-specific recovery are covered
by the [installation guide](getting-started/installation.md).

## Configure hosts

Host management is interactive and human-only:

```sh
sloosh host list
sloosh host show myhost
sloosh host add myhost --hostname server.example.com --user deploy --auth agent
sloosh host edit myhost --port 2222
sloosh host trust myhost
sloosh host rm myhost
```

Authentication choices are SSH agent, a vault-backed password, or a key-file
path. Unencrypted Ed25519/ECDSA key files sign directly. For RSA or encrypted
OpenSSH key files, keep the KeyFile profile and load that same key into the
daemon's SSH Agent. Sloosh selects only its corresponding public identity;
it does not decrypt, load, or sign RSA keys locally. Encrypted formats without
readable OpenSSH public metadata are unsupported.

If the identity is missing, the error gives a shell-quoted command targeting
the daemon's actual agent socket. Run that command yourself and retry; any key
passphrase belongs in the system tool's human prompt. A server-rejected key
instead requires checking the remote user's authorized keys. Loading other
keys does not change this profile's selected identity. KeyFile lease approval
requirements are unchanged, and Sloosh does not configure automatic loading
after an agent restart. SSH-config hosts keep their existing agent-first order.

A vault profile configured with `--auth agent` uses the default system
`$SSH_AUTH_SOCK` and can skip human lease approval once the daemon can inspect
the unlocked vault. The DMG Keychain preview supplies that state without an
approval prompt; a CLI-only cold vault remains pending because absence from an
encrypted vault cannot be inferred safely. An OpenSSH-config-backed host gets
the same automatic path only when the complete target and ProxyJump scope uses
the default agent and has no `IdentityFile` or custom `IdentityAgent`. The
lease remains process-bound and time-limited; changing a host away from that
policy makes the automatic lease unusable.

Routes can be direct, through another managed profile, or an advanced
OpenSSH ProxyJump expression:

```sh
sloosh host edit myhost --via bastion
sloosh host edit myhost --proxy-jump jump.example.com
sloosh host edit myhost --direct
```

Aliases are stable identities and cannot be renamed. Run
`sloosh host add --help` or `sloosh host edit --help` for every option.

Hosts not stored in the vault fall back to OpenSSH configuration. Sloosh
understands `Host`, `HostName`, `Port`, `User`, `IdentityFile`, `ProxyJump`,
and `IdentityAgent`, including global defaults before the first `Host`.
`Include` supports nested files, multiple quoted paths, `~/` expansion, and
lexically ordered globs. Relative paths use `~/.ssh`, including nested files;
unmatched patterns are ignored. Conditional `Host` includes retain their scope.
Unreadable files, include limits, dynamic `%`/`$` paths, `~user`, and recursive
`**` patterns fail closed rather than silently dropping connection settings.
Unsupported directives in unrelated `Host` blocks stay silent. A selected
host gets one concise diagnostic for lower-impact ignored options. Directives
known to change its endpoint, route, or host-key identity (
`ProxyCommand`, `ProxyUseFdpass`, `HostKeyAlias`, and hostname
canonicalization) fail instead of falling back to guessed settings. Because
Sloosh does not evaluate `Match` predicates, any `Match` section is a
fail-closed barrier for SSH-config-backed hosts. Direct vault profiles do not
consume unrelated SSH configuration.

## Desktop app

The macOS DMG includes the Sloosh desktop control plane and its private
`slooshd`; it does not install a public CLI. Install `sloosh` separately with
Homebrew, Cargo, or the command-line archive when terminal or Agent access is
needed. Both clients share the app daemon and state when the app is installed
in Applications; the desktop talks to that daemon directly and never shells
out to the CLI.

Setup installs the embedded Agent Skill and initializes the vault; Security
configures Touch ID, an optional 6-digit Sloosh PIN, and the shared Idle timeout.
Enabling Touch ID or PIN stores a protected copy of the vault Master Password
in the macOS login Keychain. If macOS asks, `Always Allow` avoids repeated
access prompts for that item; `Allow` grants one-time access. These actions do
not import SSH private keys or grant SSH access.

Hosts manages the same vault-backed profiles as the CLI. Unlock it with Touch
ID, the Sloosh PIN, or the vault Master Password. Native approval labels the
latter `Master Password (vault)`, not the macOS login password. PIN submission
uses `Unlock` for desktop access and `Approve` for SSH approval. Master Password and PIN entry stay
in the bundled native helper and never enter the WebView. An SSH password
entered in Hosts is transient, crosses the local command boundary as a redacted
secret, and is cleared after submission. A private-key path can be typed
directly when Finder hides `.ssh`, or selected with the file picker.

Each host row also provides manual host-key trust and an end-to-end connection
test. Trust shows the exact resolved endpoint, key algorithm, and SHA256
fingerprint. A changed key shows both stored and newly observed fingerprints
plus the owning file. Compare the new value with an independent source before
choosing `Trust host key` or `Replace host key`. Sloosh re-resolves and re-probes
before changing only `~/.sloosh/known_hosts`; it never modifies
`~/.ssh/known_hosts`. If the preview changes, the dialog refreshes without
writing. ProxyJump keys are presented dependency-first.

`sloosh host trust myhost` provides the same human-only flow in a terminal.
The connection-test action opens this trust dialog first when needed. After
all route keys have been trusted, it automatically retries the normal lease flow and
verifies the TCP connection, SSH handshake, host key,
configured authentication, and remote shell before cleaning up its reserved
test session. Opening trust directly from a host row does not start a connection
test. Removing a host deletes its vault entry, including any stored password;
existing SSH sessions stay open.

The app locks the vault session after its configured idle period and on system
sleep, screen lock, user switch, manual lock, app exit, or the absolute session
ceiling. Exact credential, timeout, and approval boundaries belong to
[SECURITY.md](../SECURITY.md).

## Authorize access

Outside Dangerous Bypass Mode, request a lease before using a host:

```sh
sloosh request myhost
```

Continue only when it reports `authorized`. If it prints a pending approval
command, a human runs that exact command in another terminal:

```sh
sloosh approve REQUEST_ID_FROM_OUTPUT
```

If the complete scope is system-SSH-agent-only, `request` activates a bounded
lease without human approval. Otherwise, a configured macOS DMG installation
shows every target and ProxyJump dependency in a bounded, scrollable scope list,
followed by direct Touch ID, approval PIN, and vault Master Password buttons.
Select one to start that secure method without a list-selection/Continue step.
Unknown host keys still require the human to verify the fingerprint in the
terminal approval flow or the unlocked desktop Hosts screen. ProxyJump routes
are validated before authorization.

## Persistent sessions

The default session preserves its working directory, environment, and
background jobs:

```sh
sloosh run myhost "cd /srv/app"
sloosh run myhost "export APP_ENV=production"
sloosh run myhost "npm test"
```

If a command returns `running`, follow its existing execution instead of
starting it again:

```sh
sloosh peek myhost
sloosh interrupt myhost
```

Interactive input and parallel sessions:

```sh
sloosh send myhost "y" --newline
sloosh open myhost deploy
sloosh run --session deploy myhost "./deploy.sh"
sloosh peek --session deploy myhost
sloosh ls --host myhost
sloosh kill --session deploy myhost
```

## File transfer

Transfers reuse the authorized SSH connection:

```sh
sloosh put myhost ./build.tar.gz /srv/app/build.tar.gz
sloosh get myhost /var/log/app.log ./app.log
```

`put` truncates the remote destination and is not remotely atomic; interruption
may leave a partial remote file. `get` refuses to overwrite an existing local
file unless `--force` is explicit. See the
[architecture](internals/architecture.md) and [security model](../SECURITY.md)
for transfer guarantees.

## Port forwarding

```sh
sloosh forward myhost -L 8080:127.0.0.1:80
sloosh forward myhost -R 9000:127.0.0.1:3000
sloosh forward ls
sloosh forward stop FORWARD_ID
```

Local forwarding binds loopback only. Remote forwarding deliberately creates
a listener on the SSH server; its exposure depends on sshd `GatewayPorts`.
Review [SECURITY.md](../SECURITY.md) before using `-R`.

## Vault and approval timeout

```sh
sloosh vault timeout
sloosh vault timeout 15
```

The timeout is shared by the desktop vault and idle CLI/Agent leases. It does
not replace approval outside the system-agent-only policy. Exact lease and
vault rules belong to [SECURITY.md](../SECURITY.md).

## Status, logs, and daemon

Start diagnosis with:

```sh
sloosh status
sloosh log -n 50
sloosh daemon status
```

The dedicated `slooshd` normally starts on demand and should not be invoked
directly. Lifecycle controls are available under `sloosh daemon --help`; use
them only when troubleshooting.

Command warnings and errors use stderr; normal command results stay on stdout.
Detached daemon diagnostics go to `~/.sloosh/daemon.log`. Operational warnings
carry a stable `diagnostic_code`; repeated background failures are summarized
with `suppressed=N` instead of printing every occurrence. When a later success
proves recovery, it is recorded once. `RUST_LOG=debug` enables more detail for
either binary. Review all logs before sharing them.

## Command reference

Run `sloosh --help` for the command list and
`sloosh <command> --help` for flags. Protocol and component details live in
[protocol.md](internals/protocol.md) and
[architecture.md](internals/architecture.md). For support, see
[SUPPORT.md](../SUPPORT.md).
