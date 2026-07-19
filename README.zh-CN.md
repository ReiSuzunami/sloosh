# sloosh

[English](./README.md) | 简体中文

[![CI](https://github.com/ReiSuzunami/sloosh/actions/workflows/ci.yml/badge.svg)](https://github.com/ReiSuzunami/sloosh/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#许可证)
[![Rust edition 2024](https://img.shields.io/badge/rust-edition%202024-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)

`sloosh` 是面向 Coding Agent 的 SSH 操作工具，解决 Agent 直接调用 `ssh` 或子进程时的
两个问题：每次 shell 调用都会丢失 `cwd`、环境变量和后台任务；建立连接通常又要求 Agent
直接持有密码或私钥。`sloosh` 通过后台 daemon 为每台主机维护长期远端 shell，并要求人类
通过带外方式批准有时限的主机 lease，使 Agent 无需接触凭据。

## 安装

从 [最新 GitHub Release](https://github.com/ReiSuzunami/sloosh/releases/latest)
下载预编译包：

- Apple silicon 和 Intel Mac：`sloosh-macos-universal.tar.gz`
- 64 位 x86 Linux：`sloosh-linux-x86_64-musl.tar.gz`

解压后将二进制安装到 `PATH` 中：

```sh
install -d "$HOME/.local/bin"
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
sloosh --version
```

无需 Rust 工具链。校验和、平台限制、升级和 crates.io 源码安装见
[安装指南](./docs/getting-started/installation.zh-CN.md)。crates.io 命令要等首次发布 crate
后才能使用。

## 60 秒快速开始

**人类操作**（只需初始化一次，在自己的终端运行）：

```sh
sloosh vault init                                   # 设置凭据库主密码
sloosh add myhost --hostname 1.2.3.4 --user deploy # 用别名登记主机
# Agent 随后运行 `sloosh request myhost` 并显示批准命令
sloosh approve <request-id>                         # 在这里粘贴并输入主密码
```

**Agent 操作：**

```sh
sloosh request myhost          # 请求访问；把批准命令交给人类，然后停止并等待
sloosh run myhost "npm test"  # 获批后在持久 shell 中执行命令
```

每个子命令的完整参数见 `sloosh <command> --help`。

## 核心模型

`sloosh` 只有一个二进制，其中包含短生命周期 CLI 和自动启动的 daemon。daemon 保存 SSH
会话；CLI 处理人类交互和本地 SFTP 路径。访问主机需要人类批准、带时限的 lease。凭据留在
加密 vault 中，不会返回给面向 Agent 的命令。

这能减少凭据暴露和误访问，但不能隔离同一 OS 用户下运行的恶意代码。依赖此边界前请阅读
英文权威文档 [`SECURITY.md`](./SECURITY.md)。

## 命令

这里只列出子命令用途；完整参数以 `sloosh <command> --help` 为准。

| 命令 | 用途 |
|---|---|
| `init` | 在人类终端中安装 Agent Skill 并初始化 vault。 |
| `skill` | 不启动 daemon，安装或检查内嵌 Agent Skill。 |
| `run` | 在主机默认或指定 session 中运行命令，等待完成或超时。 |
| `peek` | 读取 session 自上次 peek 后产生的输出。 |
| `send` | 向 session PTY 发送原始按键，例如回答交互式提示。 |
| `interrupt` | 向 session 发送 Ctrl-C。 |
| `open` | 显式创建新的命名并行 session。 |
| `ls` | 列出已知 session 及其状态。 |
| `kill` | 终止 session 和对应远端 shell。 |
| `request` | 为一个或多个主机申请访问 lease。 |
| `approve` | 在另一终端由人类批准 pending lease。 |
| `add` | 向 vault 添加凭据；仅交互使用，不提供传递 secret 的参数。 |
| `rm` | 从 vault 删除凭据。 |
| `vault` | 管理凭据库，例如首次初始化。 |
| `put` | 通过 SFTP 上传本地文件；会先截断远端目标。 |
| `get` | 通过 SFTP 原子下载；默认拒绝覆盖，除非使用 `--force`。 |
| `forward` | 创建受 lease 控制的 loopback `-L` 或远端 `-R` forward。 |
| `status` | 显示 daemon、session 和 lease 状态；遇到问题时先运行它。 |
| `daemon` | 管理 daemon；通常无需手工启动。 |
| `log` | 显示审计日志。 |

## 与 Coding Agent 配合

`skills/sloosh/` 是可直接使用的 [Agent Skill](https://agentskills.io)。它向 Agent
说明持久 session、人类批准 lease 和 `sloosh status` 等操作模型，不复制 `--help` 参数。

**Claude Code**，通过 [nerv](https://github.com/ReiSuzunami/nerv) plugin marketplace：

```text
/plugin marketplace add ReiSuzunami/nerv
/plugin install sloosh@nerv
```

**Codex**，通过同一 marketplace：

```sh
codex plugin marketplace add ReiSuzunami/nerv
codex plugin add sloosh@nerv
```

**支持 skills CLI 的 Agent**（Claude Code、Codex、Cursor 等）：

```sh
npx skills add ReiSuzunami/sloosh
```

**手工安装：**

```sh
cp -r skills/sloosh ~/.claude/skills/sloosh # Claude Code
cp -r skills/sloosh ~/.agents/skills/sloosh # Codex 及其它读取 .agents/skills 的 Agent
```

Skill-first 路径会检查 `sloosh`、说明官方安装方式，并在建议安装二进制前先征得同意。
如果先安装了二进制，请在人类自己的终端中运行组合初始化：

```sh
sloosh init
```

`sloosh init` 会安装或校验二进制内嵌的 Skill，再创建 vault。它自动检测 Codex 与
Claude Code；可用 `sloosh skill status` 检查结果。二进制本身不会调用 `npx` 或任何
Agent marketplace。

## 文档

- [文档索引](./docs/README.md)
- [安装指南](./docs/getting-started/installation.zh-CN.md)
- [安全模型（英文权威）](./SECURITY.md)
- [架构（英文权威）](./docs/internals/architecture.md)
- [线协议（英文权威）](./docs/internals/protocol.md)
- [贡献与测试（英文）](./CONTRIBUTING.md)

## 平台支持

`sloosh` 支持 macOS 和 Linux。预编译发布包覆盖 Apple silicon、Intel Mac，以及通过
musl 静态链接的 64 位 x86 Linux。Linux 运行时需要可读 procfs，以验证 peer executable
和进程 ancestry。其它 Linux CPU 架构目前需要源码构建。Windows 支持仍在规划中，需要
Named Pipe transport 和能够防止 PID 复用误判的进程 ancestry 实现。

## 路线图

Phase 2 大致顺序：

- Windows 支持（Named Pipe transport）。
- 基于远端 `tmux` 的 `--resilient` session，使 SSH 断线不再终止 session。
- 通过 Touch ID / Windows Hello 加强批准流程，同时保持 vault 加密独立于 OS keychain。
- 验证 1Password/Bitwarden `ssh-agent` 兼容性；当前已支持 ssh_config 的
  `IdentityAgent` 指令。

## 许可证

可任选以下许可证：

- [MIT License](./LICENSE-MIT)
- [Apache License, Version 2.0](./LICENSE-APACHE)

除非贡献者另有明确说明，提交到本项目的贡献按 Rust 社区惯例使用相同双许可证，不附加
其它条款。
