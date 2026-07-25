# sloosh

简体中文 | [English](./README.en.md)

[![CI](https://github.com/ReiSuzunami/sloosh/actions/workflows/ci.yml/badge.svg)](https://github.com/ReiSuzunami/sloosh/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#许可证)

为 Coding Agent 提供持久 SSH 会话与带外人工批准；Agent 无需接触密码或私钥。

## 安装

预编译版本发布后，从
[最新 GitHub Release](https://github.com/ReiSuzunami/sloosh/releases/latest)
下载：

- macOS 桌面 App 与 CLI：`Sloosh-<version>-macos-universal.dmg`
- macOS 独立 CLI：`sloosh-macos-universal.tar.gz`
- Linux x86_64：`sloosh-linux-x86_64-musl.tar.gz`

Homebrew tap 与 crates.io 只提供 CLI，不包含或构建桌面 App。macOS 桌面 App
与 DMG 仅通过 GitHub Releases 发布。

校验和、平台要求与升级步骤见[安装指南](./docs/getting-started/installation.zh-CN.md)。

## 交给 Agent 安装

**将下面的完整 Prompt 粘贴给你的 Agent。/ Paste this prompt to your agent.**

```text
你是我的 sloosh 安装向导。

1. 检测操作系统与架构，执行 `command -v sloosh && sloosh --version`。仅使用官方仓库
   `https://github.com/ReiSuzunami/sloosh`。若未安装或版本过旧，检查最新 Release：
   有 Release 时选择对应 DMG/压缩包并验证 `SHA256SUMS`；没有时说明 Rust 1.85+
   源码构建方案。任何安装前先征得我同意。禁止 `curl | sh`、静默调用包管理器、
   绕过平台保护，禁止索取或显示密码、SSH 密钥、vault secret 或 lease token。
2. 二进制可用后，解释 `sloosh init`，让我在自己的交互式终端运行。你不得代跑、
   伪造 TTY、输入或读取 secret。
3. 等我确认完成后，只读运行 `sloosh skill status --agent auto` 和 `sloosh status`，
   报告结果。任何主机访问仍须带外人工批准。
```

不使用 Agent 时，按[使用手册](./docs/manual.zh-CN.md)完成初始化与首次连接。

## 从源码构建

需要 Rust 1.85+ 与 C/C++ 构建工具链：

```sh
git clone https://github.com/ReiSuzunami/sloosh.git
cd sloosh
cargo build --release --locked
```

二进制位于 `target/release/sloosh`。

## 文档

- [使用手册](./docs/manual.zh-CN.md)
- [安装与升级](./docs/getting-started/installation.zh-CN.md)
- [安全模型](./SECURITY.md)
- [架构](./docs/internals/architecture.md) · [协议](./docs/internals/protocol.md)
- [贡献](./CONTRIBUTING.md) · [支持](./SUPPORT.md)
- [完整文档索引](https://github.com/ReiSuzunami/sloosh/blob/main/docs/README.md)

## 许可证

[MIT](./LICENSE-MIT) 或 [Apache-2.0](./LICENSE-APACHE)，任选其一。
