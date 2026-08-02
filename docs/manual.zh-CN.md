# Sloosh 使用手册

[English](manual.md) | 简体中文

本手册面向人类用户，介绍初始化与日常 CLI、桌面端操作。Agent 应遵循内嵌的
[Agent Skill](../skills/sloosh/SKILL.md)；安全保证与限制以
[SECURITY.md](../SECURITY.md) 为准。

## 初始化

请在人类自己的交互式终端中运行：

```sh
sloosh init
```

它会安装内嵌 Agent Skill 并初始化凭据 vault。仅命令行安装中，password、key-file 与
自定义 Agent scope 由人类在另一终端批准；仅使用默认系统 SSH Agent 的 scope 自动授权。
macOS 桌面 App 通过自身的 Setup 与 Security 配置 Keychain、Touch ID 与可选审批 PIN。

验证结果：

```sh
sloosh skill status --agent auto
sloosh status
```

安装、校验和、升级与平台排障见[安装指南](getting-started/installation.zh-CN.md)。

## 配置主机

主机管理是交互式、人类专用操作：

```sh
sloosh host list
sloosh host show myhost
sloosh host add myhost --hostname server.example.com --user deploy --auth agent
sloosh host edit myhost --port 2222
sloosh host trust myhost
sloosh host rm myhost
```

认证方式包括 SSH agent、vault 加密密码，或未加密 Ed25519/ECDSA 私钥路径。RSA 与
加密私钥必须先载入 ssh-agent。

使用 `--auth agent` 的 vault profile 只使用默认系统 `$SSH_AUTH_SOCK`；daemon 能检查
已解锁 vault 后可跳过人工 lease 批准。DMG Keychain 预览可无审批弹窗提供该状态；仅 CLI
的冷启动 vault 仍会 pending，因为不能把加密 vault 中“看不到”误判成“不存在”。OpenSSH
配置主机只有在目标与完整 ProxyJump scope 都使用默认 Agent，且没有 `IdentityFile` 或
自定义 `IdentityAgent` 时才走相同自动路径。lease 仍绑定进程并受超时限制；主机离开该
策略后，自动 lease 会立即失效。

路由可以直连、经过另一条受管主机配置，或使用高级 OpenSSH ProxyJump：

```sh
sloosh host edit myhost --via bastion
sloosh host edit myhost --proxy-jump jump.example.com
sloosh host edit myhost --direct
```

alias 是稳定身份，不能改名。所有选项见 `sloosh host add --help` 与
`sloosh host edit --help`。

未存入 vault 的主机会回退到 OpenSSH 配置。Sloosh 支持 `Host`、`HostName`、
`Port`、`User`、`IdentityFile`、`ProxyJump` 与 `IdentityAgent`，也支持首个
`Host` 前的全局默认值。其他 `Host` 块中的不支持指令保持静默；命中目标的低影响
未实现选项只生成一条精简诊断。已知会改变 endpoint、路由或 host-key 身份的
`Include`、`ProxyCommand`、`ProxyUseFdpass`、`HostKeyAlias` 与 hostname
canonicalization 会直接失败，不会猜测默认设置。Sloosh 不解析 `Match` 条件，
所以任何 `Match` 区段都会让 SSH-config-backed 主机 fail closed。直连 vault
profile 不读取无关 SSH 配置。

## 桌面 App

macOS DMG 包含 Sloosh 桌面控制面与私有 `slooshd`，不会安装公共 CLI。需要终端或
Agent 访问时，请另用 Homebrew、Cargo 或命令行压缩包安装 `sloosh`。App 位于
“应用程序”时，两个客户端会共用 App daemon 与状态；桌面端直接连接 daemon，不会
通过 shell 调用 CLI。

Setup 安装内嵌 Agent Skill 并初始化 vault；Security 配置 Touch ID、可选的 6 位
Sloosh PIN 与共用 vault 空闲期。这些操作不会导入 SSH 私钥，也不会批准主机。

Hosts 管理与 CLI 相同的 vault 主机配置，可使用 Touch ID、Sloosh PIN 或 Master
Password 解锁。Master Password 与 PIN 只在内置原生 helper 中输入，不会进入 WebView。
Hosts 中输入的 SSH password 仅短暂存在，通过本地命令边界时使用脱敏 secret，提交后
立即清空。Finder 隐藏 `.ssh` 时，可直接输入私钥完整路径，也可继续使用文件选择器。

每条主机记录还提供手动 host-key 信任与端到端连接测试。信任流程会显示实际解析的
endpoint、key algorithm 与 SHA256 指纹；key 发生变化时，同时显示旧、新指纹及其来源文件。
请通过独立来源核对新指纹，再直接选择新增或替换。Sloosh 写入前会重新解析路由并重新探测，
且只会修改 `~/.sloosh/known_hosts`，绝不修改 `~/.ssh/known_hosts`。若预览期间状态又有
变化，弹窗只刷新内容，不执行写入。ProxyJump key 按依赖顺序逐个展示。

终端中的 `sloosh host trust myhost` 提供同样的人类专用流程。连接测试遇到未信任或变化的
key 时会先打开该弹窗；成功新增或替换后自动重试普通 lease 流程，并依次验证 TCP、
SSH handshake、host key、配置的认证方式与远端 shell，最后清理专用测试 session。

达到配置的空闲期，或发生系统睡眠、锁屏、切换用户、手动锁定、退出 App、绝对会话上限时，
App 会锁定 vault session。凭据、超时与审批边界以
[SECURITY.md](../SECURITY.md) 为准。

## 批准访问

使用主机前先请求 lease：

```sh
sloosh request myhost
```

仅在输出 `authorized` 后继续。如果输出 pending 审批命令，由人类在另一终端执行原命令：

```sh
sloosh approve REQUEST_ID_FROM_OUTPUT
```

若完整 scope 仅使用系统 SSH Agent，`request` 无需人工批准即可激活限时 lease。其他
scope 在配置完成的 macOS DMG 安装中会先用有界、可滚动列表显示全部目标主机与
ProxyJump 依赖，再直接提供 Touch ID、审批 PIN、vault Master Password 三个按钮；
点击即进入对应安全认证，不再先列表选择再点 Continue。未知 host key 仍需人类在终端
审批流程或已解锁的桌面 Hosts 页面核对指纹；ProxyJump 路由会在授权前校验。

## 持久会话

默认会话会保留工作目录、环境变量与后台任务：

```sh
sloosh run myhost "cd /srv/app"
sloosh run myhost "export APP_ENV=production"
sloosh run myhost "npm test"
```

命令返回 `running` 时，应继续查看原执行，不要重复启动：

```sh
sloosh peek myhost
sloosh interrupt myhost
```

交互输入与并行会话：

```sh
sloosh send myhost "y" --newline
sloosh open myhost deploy
sloosh run --session deploy myhost "./deploy.sh"
sloosh peek --session deploy myhost
sloosh ls --host myhost
sloosh kill --session deploy myhost
```

## 文件传输

传输复用已授权的 SSH 连接：

```sh
sloosh put myhost ./build.tar.gz /srv/app/build.tar.gz
sloosh get myhost /var/log/app.log ./app.log
```

`put` 会截断远端目标且不保证远端原子性；中断可能留下不完整文件。`get` 默认拒绝覆盖
已有本地文件，只有明确使用 `--force` 才覆盖。传输保证见
[架构](internals/architecture.md)与[安全模型](../SECURITY.md)。

## 端口转发

```sh
sloosh forward myhost -L 8080:127.0.0.1:80
sloosh forward myhost -R 9000:127.0.0.1:3000
sloosh forward ls
sloosh forward stop FORWARD_ID
```

本地转发只绑定 loopback。远程转发会主动在 SSH 服务器创建监听，其暴露范围取决于 sshd
`GatewayPorts`；使用 `-R` 前请阅读 [SECURITY.md](../SECURITY.md)。

## Vault 与审批超时

```sh
sloosh vault timeout
sloosh vault timeout 15
```

该值由桌面 vault 与空闲 CLI/Agent lease 共用，但不会替代系统 Agent 自动策略之外的批准。
精确 lease 与 vault 规则以 [SECURITY.md](../SECURITY.md) 为准。

## 状态、日志与 daemon

排障先运行：

```sh
sloosh status
sloosh log -n 50
sloosh daemon status
```

专用 `slooshd` 通常按需自动启动，不应直接运行。生命周期控制命令见
`sloosh daemon --help`，只在排障时使用。

命令警告与错误写入 stderr，正常结果保留在 stdout。后台 daemon 诊断写入
`~/.sloosh/daemon.log`。运行期警告包含稳定 `diagnostic_code`；重复后台故障以
`suppressed=N` 聚合，不会逐条刷屏；后续成功能证明恢复时，只记录一次恢复事件。
可用 `RUST_LOG=debug` 为任一二进制启用更多细节；分享前必须检查并脱敏日志。

## 命令参考

运行 `sloosh --help` 查看命令列表，运行 `sloosh <command> --help` 查看参数。
协议与组件细节见[协议](internals/protocol.md)和[架构](internals/architecture.md)；
支持渠道见 [SUPPORT.md](../SUPPORT.md)。
