# sloosh

[English](./README.md) | 简体中文

[![CI](https://github.com/ReiSuzunami/sloosh/actions/workflows/ci.yml/badge.svg)](https://github.com/ReiSuzunami/sloosh/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#许可证)

为 Coding Agent 提供持久 SSH 会话与人类批准的凭据访问。

## 安装

从 [最新 GitHub Release](https://github.com/ReiSuzunami/sloosh/releases/latest)
下载对应平台的预编译包：

- macOS DMG（Apple silicon 或 Intel）：`Sloosh-<version>-macos-universal.dmg`
- macOS CLI 压缩包（Apple silicon 或 Intel）：`sloosh-macos-universal.tar.gz`
- Linux x86_64：`sloosh-linux-x86_64-musl.tar.gz`

使用 DMG 时，双击 `Install Sloosh`。安装器会把 `Sloosh.app` 复制到“应用程序”，在路径
可用时创建 `~/.local/bin/sloosh`，推出磁盘映像，并询问是否把 DMG 移到废纸篓。CLI
路径上已有的不相关项目会保留。
打开 Sloosh 后，可以安装内置 Agent Skill、初始化 vault，并启用 Touch ID 或可选的 6 位
审批 PIN。登记前，App 会说明 macOS login Keychain 中保存的内容，以及随后可能出现的原生
访问提示。完整 CLI 会与 App 一起安装并继续保留。
更新时若 Sloosh 正在运行，安装器会先明确确认；正常退出等待 5 秒后仍未关闭，才会强制退出。

使用压缩包时，解压后将二进制安装到 `PATH` 中：

```sh
install -d "$HOME/.local/bin"
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
sloosh --version
```

校验和与平台说明见[安装指南](./docs/getting-started/installation.zh-CN.md)。

## 首次设置

推荐先安装 Agent Skill，再由 Skill 检查 `sloosh` 二进制，并指导人类完成安装：

```sh
# Codex
codex plugin marketplace add ReiSuzunami/nerv
codex plugin add sloosh@nerv

# 任何兼容 Agent Skills 的 Agent
npx skills add ReiSuzunami/sloosh
```

Claude Code 用户可以添加 `ReiSuzunami/nerv` plugin marketplace，再安装
`sloosh@nerv`。这些包管理命令只分发 Skill；Skill 在建议安装二进制前会先征得同意。

如果先安装了二进制，请在人类自己的终端中运行：

```sh
sloosh init
```

`sloosh init` 会安装二进制内嵌的 Skill，并初始化凭据 vault。macOS DMG 版本还会登记
Touch ID，用于后续 lease 请求；登记前 CLI 会解释 login Keychain 条目、可能出现的
`Sloosh Approval` 提示，以及 `Allow` 和 `Always Allow` 的区别。已有 vault 时重新运行
`sloosh init` 即可启用。它自动检测
Codex 与 Claude Code；可用 `sloosh skill status` 检查结果。二进制本身不会调用 `npx`
或任何 Agent marketplace。

登记后，`sloosh request` 会先显示原生的精确主机列表确认，再以 Touch ID 或可选审批 PIN
完成授权，不再要求另开终端。PIN 使用持久退避，连续失败 15 次后禁用，并且不会消耗 Master
Password 的失败次数。取消、未登记以及源码/压缩包构建会退回 `sloosh approve`。首次遇到未知 SSH
host key 时也仍使用终端审批，以便人类核对指纹。

Linux 不需要 Keychain、Touch ID 或原生 helper 权限。`sloosh init` 结束时会明确说明：后续
pending lease 需要由人类在另一终端执行输出中的 `sloosh approve <ID>` 命令。

## 管理主机

桌面 App 提供锁定的 Hosts 页面，用于管理 vault 中的连接配置。认证方式可明确选择 SSH
agent、vault 加密密码或未加密私钥路径；路由可选择直连、经过另一条受管主机配置，或高级
OpenSSH ProxyJump。使用 Touch ID、6 位 Sloosh PIN 或 Master Password 解锁一次后，Rust
桌面进程会在共用的 1/5/15/30 分钟空闲期内保留可零化会话；macOS 睡眠、锁屏或切换用户、
手动锁定、退出 App 或达到固定 8 小时上限都会清除它。Master Password 与 PIN 始终由原生
helper 输入。桌面端 SSH Password 仅短暂
存在于本地表单，通过 Tauri 命令边界时由脱敏 secret 类型承载，提交后立即清空。CLI 提供
相同的人类专用管理能力：

```sh
sloosh host list
sloosh host show myhost
sloosh host add myhost --hostname server.example.com --user deploy --auth agent
sloosh host edit myhost --port 2222 --via bastion
sloosh host edit myhost --auth key-file --key-file ~/.ssh/id_ed25519
sloosh host rm myhost
sloosh vault timeout 15
```

`sloosh vault timeout` 可查看当前值。在 GUI 或 CLI 中修改后，桌面 vault 与空闲的 CLI/Agent
lease 会共用该值；逐请求主机审批与 8 小时绝对 lease 上限仍然独立。

alias 是稳定的 lease 与 ProxyJump 身份，因此编辑时不能改名。旧的 `sloosh add` 与
`sloosh rm` 仍为兼容保留。所有管理命令都不会输出认证材料。

## 从源码构建

需要 Rust 1.85 或更高版本，以及可用的 C/C++ 构建工具链。

```sh
git clone https://github.com/ReiSuzunami/sloosh.git
cd sloosh
cargo build --release --locked
```

生成的二进制位于 `target/release/sloosh`。

## 许可证

可任选 [MIT](./LICENSE-MIT) 或 [Apache-2.0](./LICENSE-APACHE) 许可证。
