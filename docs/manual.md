# Sloosh manual

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
Command-line-only installations use approval from another human terminal. The
macOS desktop app configures Keychain access, Touch ID, and an optional
approval PIN through its own Setup and Security screens.

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
sloosh host rm myhost
```

Authentication choices are SSH agent, a vault-backed password, or an
unencrypted Ed25519/ECDSA key path. RSA and encrypted private keys must be
loaded into ssh-agent.

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
Unsupported directives in unrelated `Host` blocks stay silent. A selected
host gets one concise diagnostic for lower-impact ignored options. Directives
known to change its endpoint, route, or host-key identity (`Include`,
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
configures Touch ID, an optional 6-digit Sloosh PIN, and the shared vault
timeout. These actions do not import SSH private keys or approve a host.

Hosts manages the same vault-backed profiles as the CLI. Unlock it with Touch
ID, the Sloosh PIN, or the Master Password. Master Password and PIN entry stay
in the bundled native helper and never enter the WebView. An SSH password
entered in Hosts is transient, crosses the local command boundary as a redacted
secret, and is cleared after submission.

The app locks the vault session after its configured idle period and on system
sleep, screen lock, user switch, manual lock, app exit, or the absolute session
ceiling. Exact credential, timeout, and approval boundaries belong to
[SECURITY.md](../SECURITY.md).

## Authorize access

Request a lease before using a host:

```sh
sloosh request myhost
```

Continue only when it reports `authorized`. If it prints a pending approval
command, a human runs that exact command in another terminal:

```sh
sloosh approve REQUEST_ID_FROM_OUTPUT
```

On a configured macOS DMG installation, Touch ID or the approval PIN may
complete the request directly. Unknown host keys still require the human to
verify the fingerprint. ProxyJump routes are validated before approval.

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
not replace per-request host approval. Exact lease and vault rules belong to
[SECURITY.md](../SECURITY.md).

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
