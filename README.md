# sloosh

简体中文 | [English](./README.en.md)

[![CI](https://github.com/ReiSuzunami/sloosh/actions/workflows/ci.yml/badge.svg)](https://github.com/ReiSuzunami/sloosh/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#许可证)

为 Coding Agent 提供持久 SSH 会话；系统 SSH Agent 凭据可自动授权，密码、私钥文件与
自定义 Agent 仍由人类带外批准。Agent 无需接触 secret。

## 安装

预编译版本发布后，从
[最新 GitHub Release](https://github.com/ReiSuzunami/sloosh/releases/latest)
下载：

- macOS 桌面控制面：`Sloosh-<version>-macos-universal.dmg`
- macOS 命令行包：`sloosh-macos-universal.tar.gz`
- Linux x86_64：`sloosh-linux-x86_64-musl.tar.gz`

DMG 只安装桌面控制面及其私有 daemon，不会把 `sloosh` CLI 放进 `PATH`。
Homebrew、crates.io 与命令行压缩包提供 `sloosh` 和配套 `slooshd`，不包含或构建
桌面 App。macOS 桌面 App 与 DMG 仅通过 GitHub Releases 发布。

校验和、平台要求与升级步骤见[安装指南](./docs/getting-started/installation.zh-CN.md)。

## 交给 Agent 安装

**将下面的完整 Prompt 粘贴给你的 Agent。/ Paste this prompt to your agent.**

```text
你是我的 sloosh 安装向导。

1. 检测操作系统与架构，执行 `command -v sloosh && sloosh --version`。仅使用官方仓库
   `https://github.com/ReiSuzunami/sloosh`。若未安装或版本过旧，检查最新 Release：
   为 CLI 选择 Homebrew 或对应命令行压缩包并验证 `SHA256SUMS`；没有 Release 时说明
   Rust 1.85+ 源码构建方案。macOS DMG 是可选桌面控制面，不提供 CLI。任何安装前先
   征得我同意。禁止 `curl | sh`、静默调用包管理器、绕过平台保护，禁止索取或显示
   密码、SSH 密钥、vault secret 或 lease token。不要直接运行 `slooshd`。
2. CLI 可用后，解释 `sloosh init`，让我在自己的交互式终端运行。你不得代跑、伪造
   TTY、输入或读取 secret。如果我还安装了桌面 App，引导我亲自打开 Setup/Security
   完成原生解锁设置。
3. 等我确认完成后，只读运行 `sloosh skill status --agent auto` 和 `sloosh status`，
   报告结果。仅使用默认系统 SSH Agent 且无私钥文件 fallback 的完整主机范围会自动
   获得限时 lease；其他主机访问仍须带外人工批准。未知或变化的 host key 始终由我确认。
```

不使用 Agent 时，按[使用手册](./docs/manual.zh-CN.md)完成初始化与首次连接。

## 从源码构建

需要 Rust 1.85+ 与 C/C++ 构建工具链：

```sh
git clone https://github.com/ReiSuzunami/sloosh.git
cd sloosh
cargo build --release --bins --locked
```

命令行客户端与 daemon 分别位于 `target/release/sloosh` 和
`target/release/slooshd`。

## 文档

- [使用手册](./docs/manual.zh-CN.md)
- [安装与升级](./docs/getting-started/installation.zh-CN.md)
- [安全模型](./SECURITY.md)
- [架构](./docs/internals/architecture.md) · [协议](./docs/internals/protocol.md)
- [贡献](./CONTRIBUTING.md) · [支持](./SUPPORT.md)
- [完整文档索引](https://github.com/ReiSuzunami/sloosh/blob/main/docs/README.md)

## 许可证

[MIT](./LICENSE-MIT) 或 [Apache-2.0](./LICENSE-APACHE)，任选其一。
