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

它会安装内嵌 Agent Skill 并初始化凭据 vault。macOS DMG 流程还可能配置 Keychain、
Touch ID 与可选审批 PIN；Linux 和 standalone build 由人类在另一终端批准。

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
sloosh host rm myhost
```

认证方式包括 SSH agent、vault 加密密码，或未加密 Ed25519/ECDSA 私钥路径。RSA 与
加密私钥必须先载入 ssh-agent。

路由可以直连、经过另一条受管主机配置，或使用高级 OpenSSH ProxyJump：

```sh
sloosh host edit myhost --via bastion
sloosh host edit myhost --proxy-jump jump.example.com
sloosh host edit myhost --direct
```

alias 是稳定身份，不能改名。所有选项见 `sloosh host add --help` 与
`sloosh host edit --help`。

## 桌面 App

macOS DMG 包含 Sloosh 桌面 App。Setup 安装内嵌 Agent Skill 并初始化 vault；
Security 配置 Touch ID、可选的 6 位 Sloosh PIN 与共用 vault 空闲期。这些操作不会
导入 SSH 私钥，也不会批准主机。

Hosts 管理与 CLI 相同的 vault 主机配置，可使用 Touch ID、Sloosh PIN 或 Master
Password 解锁。Master Password 与 PIN 只在内置原生 helper 中输入，不会进入 WebView。
Hosts 中输入的 SSH password 仅短暂存在，通过本地命令边界时使用脱敏 secret，提交后
立即清空。

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

配置完成的 macOS DMG 安装可直接通过 Touch ID 或审批 PIN 完成请求。未知 host key
仍需人类核对指纹；ProxyJump 路由会在批准前完成校验。

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

该值由桌面 vault 与空闲 CLI/Agent lease 共用，但不会替代逐请求主机批准。精确 lease
与 vault 规则以 [SECURITY.md](../SECURITY.md) 为准。

## 状态、日志与 daemon

排障先运行：

```sh
sloosh status
sloosh log -n 50
sloosh daemon status
```

daemon 通常按需自动启动。直接控制命令见 `sloosh daemon --help`，只在排障时使用。

## 命令参考

运行 `sloosh --help` 查看命令列表，运行 `sloosh <command> --help` 查看参数。
协议与组件细节见[协议](internals/protocol.md)和[架构](internals/architecture.md)；
支持渠道见 [SUPPORT.md](../SUPPORT.md)。
