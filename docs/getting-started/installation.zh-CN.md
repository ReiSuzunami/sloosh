# 安装

[English](installation.md) | 简体中文

GitHub Releases 是主要安装渠道，提供预编译二进制，用户无需 Rust 或 C 编译器。
crates.io 是为 Rust 用户准备的次要源码安装渠道，始终会在本机编译。

## 预编译二进制

从 [最新 Release](https://github.com/ReiSuzunami/sloosh/releases/latest) 下载：

| 平台 | 文件 |
|---|---|
| macOS 11 或更新版本，Apple silicon 或 Intel | `Sloosh-<version>-macos-universal.dmg` 或 `sloosh-macos-universal.tar.gz` |
| Linux x86_64，且 procfs 可读 | `sloosh-linux-x86_64-musl.tar.gz` |

同时下载 `SHA256SUMS`，安装前校验所选文件。

macOS DMG：

```sh
version=0.1.0
dmg="Sloosh-$version-macos-universal.dmg"
grep "  $dmg$" SHA256SUMS | shasum -a 256 -c -
open "$dmg"
```

双击 `Install Sloosh`，检查确认信息后选择“Install”。安装器会把 `Sloosh.app` 复制到
“应用程序”，并在路径可用时创建 `~/.local/bin/sloosh`。随后它会推出磁盘映像，并询问
是否把下载的 DMG 移到废纸篓。如果 CLI 路径上已有不相关的文件或链接，安装器会保留它并
提示链接未改变。

App、CLI 与 daemon 故意共用同一份真实 executable。不要把 CLI 另行复制出来；CLI 会拒绝
从不同 executable path 运行的 daemon。

macOS 压缩包备选方式：

```sh
grep '  sloosh-macos-universal.tar.gz$' SHA256SUMS | shasum -a 256 -c -
tar -xzf sloosh-macos-universal.tar.gz
install -d "$HOME/.local/bin"
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
```

Linux：

```sh
grep '  sloosh-linux-x86_64-musl.tar.gz$' SHA256SUMS | sha256sum -c -
tar -xzf sloosh-linux-x86_64-musl.tar.gz
install -d "$HOME/.local/bin"
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
```

如果需要，把 `$HOME/.local/bin` 加入 `PATH`，然后验证：

```sh
sloosh --version
```

macOS 安装器、App 与二进制使用 ad-hoc 签名，目前没有 Developer ID 签名或
notarization。首次运行可能被 macOS 阻止。验证校验和后双击 `Install Sloosh`，再到
“系统设置 > 隐私与安全性”为 Install Sloosh 选择“仍要打开”，然后重试。这是未公证
社区构建的预期安装流程。

Linux 二进制通过 musl 静态链接，以兼容常见 Linux 发行版。但 `sloosh` 仍需要 procfs
验证 peer executable 和进程 ancestry；静态链接不会消除这项运行时要求。其它 Linux
架构目前需要源码构建。

## 首次设置

在人类自己的终端中运行组合初始化：

```sh
sloosh init
```

这个仅限人类交互的命令会先安装当前二进制内嵌的 Agent Skill，再创建凭据 vault。DMG
安装还会把 vault 密码登记到本机 login Keychain，并以 Touch ID 和指纹登记状态比对保护。已有 vault 时，
重新运行 `sloosh init`，输入一次 vault 密码即可启用 Touch ID。源码构建与独立 CLI 压缩包
不含原生 helper，继续使用终端审批。

重复运行是安全的，已有 vault 不会改变。各步骤不是事务：如果 vault、daemon 或 Touch ID
随后报错，已经安装的 Skill 会保留，修复问题后可直接重试。系统中登记的指纹变化会使
Keychain 项目失效；重新运行 `sloosh init` 即可登记。

DMG App 也提供相同的设置能力：Setup 安装内置 Skill 并初始化 vault，Security 启用 Touch ID
或可选的 6 位 PIN。Master Password 与 PIN 只在内置原生 helper 中输入，不会进入 WebView。
没有 Touch ID 的设备可以使用 PIN。

默认的 `--agent auto` 会为检测到的所有 Agent 安装，路径如下：

| Agent | Skill 目录 |
|---|---|
| Codex 与兼容 Agent Skills 的读取器 | `~/.agents/skills/sloosh` |
| Claude Code | `~/.claude/skills/sloosh` |

存在 `~/.agents` 或 `~/.codex` 时视为 Codex，存在 `~/.claude` 时视为 Claude Code。
如果没有检测到 Agent，则使用兼容 Codex 的通用路径。也可通过 `--agent codex`、
`--agent claude` 或 `--agent all` 明确选择。

以下独立命令不会启动 daemon，也不会访问 vault：

```sh
sloosh skill install --agent auto
sloosh skill status --agent auto
```

由 sloosh 安装且未改动的旧 Skill 会随二进制升级。外部管理或本地修改过的 Skill 默认保留。
只有确定要替换时，才对 `skill install` 使用 `--force`，或对 `init` 使用
`--force-skill`。Sloosh 不会调用 `npx` 或 Agent marketplace；它们只是可选的 Skill
分发渠道。

## 升级

替换二进制前先停止 daemon。活跃 session、forward、pending request 和 lease 都在内存中，
停止 daemon 后会丢失。

```sh
sloosh daemon stop
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
sloosh --version
sloosh skill install
```

如果使用 DMG 安装，打开新版 DMG 并运行 `Install Sloosh`。替换已有的有效安装时，安装器
会先停止旧 daemon，再进行 staged replacement；指向正确位置的 CLI 链接会保留。确认框会
提示：停止 daemon 会结束活跃 session 和 forward。

这个顺序也避免 Linux 上旧 daemon 继续从已替换的 executable 运行；新 CLI 会拒绝无法通过
`/proc/<pid>/exe` 验证的 peer。

如果原地替换已使旧 Linux daemon 显示为 `(deleted)`，且 CLI 拒绝其 socket，运行
`pgrep -u "$(id -u)" -af 'sloosh daemon run'` 定位并确认进程，再执行 `kill <pid>` 后
重试；CLI 会清理 stale socket 并启动新二进制。

## 从 crates.io 安装

首次发布 crate 后，可通过此渠道下载源码并编译。需要 Rust 1.85 或更新版本，以及可用的
C/C++ 工具链：

```sh
cargo install sloosh --locked
```

二进制通常安装到 `$HOME/.cargo/bin`。此渠道适合 Rust 用户，不是免构建安装方式。

从仓库 checkout 构建时，见 README 中的
[源码构建步骤](../../README.zh-CN.md#从源码构建)。
