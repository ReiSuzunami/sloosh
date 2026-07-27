# 安装

[English](installation.md) | 简体中文

GitHub Releases 是有版本发布后的主要安装渠道，提供预编译二进制，用户无需 Rust 或 C
编译器。如果 latest-release 页面尚无版本，请使用下文的源码构建步骤。crates.io 是为
Rust 用户准备的次要源码安装渠道，始终会在本机编译。Homebrew tap 与 crates.io 安装
命令行包（`sloosh` 及配套 `slooshd`）；桌面 App 和 DMG 仅通过 GitHub Releases 发布。

## 预编译二进制

版本可用时，从
[最新 Release](https://github.com/ReiSuzunami/sloosh/releases/latest) 下载：

| 平台 | 文件 |
|---|---|
| macOS 11 或更新版本，Apple silicon 或 Intel | `Sloosh-<version>-macos-universal.dmg` 或 `sloosh-macos-universal.tar.gz` |
| Linux x86_64，且 procfs 可读 | `sloosh-linux-x86_64-musl.tar.gz` |

同时下载 `SHA256SUMS`，安装前校验所选文件。

macOS DMG：

```sh
version=0.2.1
dmg="Sloosh-$version-macos-universal.dmg"
grep "  $dmg$" SHA256SUMS | shasum -a 256 -c -
open "$dmg"
```

双击 `Install Sloosh`，检查确认信息后选择“Install”。安装器会先停止任何正在运行的
sloosh daemon，再把 `Sloosh.app` 复制到“应用程序”；这也包括此前由 Homebrew、Cargo、
压缩包或源码构建启动的 daemon。停止 daemon 会结束活跃 session 与 forward。安装器
不会安装公共 CLI，也不会向 `PATH` 写入任何内容。由早期合并式 bundle 升级时，它只
删除目标字符串精确指向同一 App 旧 helper 的 `~/.local/bin/sloosh` 符号链接；其它文件
或链接一律保留。随后它会推出磁盘映像，并询问是否把下载的 DMG 移到废纸篓。

App bundle 中的 Tauri 桌面程序位于 `Contents/MacOS/Sloosh`，私有 daemon 位于
`Contents/Helpers/slooshd`，并且刻意不包含公共 `sloosh` executable。桌面端通过
本地协议直接连接 daemon，不会通过 shell 调用 CLI。

macOS 压缩包备选方式：

```sh
grep '  sloosh-macos-universal.tar.gz$' SHA256SUMS | shasum -a 256 -c -
tar -xzf sloosh-macos-universal.tar.gz
install -d "$HOME/.local/bin"
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
install -m 0755 sloosh-*/slooshd "$HOME/.local/bin/slooshd"
```

Linux：

```sh
grep '  sloosh-linux-x86_64-musl.tar.gz$' SHA256SUMS | sha256sum -c -
tar -xzf sloosh-linux-x86_64-musl.tar.gz
install -d "$HOME/.local/bin"
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
install -m 0755 sloosh-*/slooshd "$HOME/.local/bin/slooshd"
```

如果需要，把 `$HOME/.local/bin` 加入 `PATH`，然后验证：

```sh
sloosh --version
slooshd --version
```

日常使用时由客户端或桌面 App 管理 `slooshd`，不要直接启动它。

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

这个仅限人类交互的命令会先安装客户端内嵌的 Agent Skill，再创建凭据 vault。仅安装
命令行包时使用终端审批；Linux 无需 Keychain 或生物识别权限，初始化会明确输出后续
pending lease 所需的另一终端 `sloosh approve <ID>` 流程。

原生设置由桌面 App 管理。打开 Setup 与 Security，在同一个 vault 上完成初始化或解锁，
并把 vault 密码登记到 login Keychain，以 Touch ID 或可选本地 PIN 保护。独立分发的 CLI
不会直接执行原生 helper。App 位于“应用程序”时，CLI 与桌面端会共用 App 私有 daemon；
人类在 App 中完成登记后，CLI 发起的 lease request 仍可使用原生批准。`Always Allow`
可避免重复 Keychain 提示，`Allow` 只授权一次。

重复运行是安全的，已有 vault 不会改变。各步骤不是事务：如果 vault、daemon 或 Touch ID
随后报错，已经安装的 Skill 会保留，修复问题后可直接重试。系统中登记的指纹变化会使
Keychain 项目失效；重新运行 `sloosh init` 即可登记。

DMG App 也提供相同的设置能力：Setup 安装内置 Skill 并初始化 vault，Security 配置原生
解锁与共用空闲期，Hosts 管理连接配置。Setup 不会导入 SSH 私钥，也不会批准主机。后续见
[使用手册的桌面 App 章节](../manual.zh-CN.md#桌面-app)。

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
install -m 0755 sloosh-*/slooshd "$HOME/.local/bin/slooshd"
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
sloosh --version
sloosh skill install
```

如果使用 DMG 安装，打开新版 DMG 并运行 `Install Sloosh`。无论首次安装还是升级，安装器
都会先停止占用共用 socket 的 daemon，再安装 App helper；精确匹配旧 DMG helper 的 CLI
链接会被删除，Homebrew、Cargo、压缩包或用户自管的 CLI 不会改变。确认框会提示：停止
daemon 会结束活跃 session 和 forward。若 GUI 正在运行，同一确认框会说明必须退出；
安装器先请求正常退出，等待 5 秒后才在用户已确认的前提下强制退出。旧 GUI 仍在运行时
不会开始替换。

这个顺序也避免 Linux 上旧 daemon 继续从已替换的 executable 运行；新 CLI 会拒绝无法通过
`/proc/<pid>/exe` 验证的 peer。

如果原地替换已使旧 Linux daemon 显示为 `(deleted)`，且 CLI 拒绝其 socket，运行
`pgrep -u "$(id -u)" -af 'slooshd'` 定位并确认 executable path，再执行 `kill <pid>`
后重试；CLI 会清理 stale socket 并启动新 daemon。

## CLI 包管理器

Homebrew 从项目 tap 安装预编译命令行包：

```sh
brew install ReiSuzunami/tap/sloosh
```

Formula 会安装 `sloosh` 与由其管理的 `slooshd`，但不安装桌面 App，也不生成 DMG。

也可从 crates.io 下载源码并在本机编译命令行包。需要 Rust 1.85 或更新版本，以及
可用的 C/C++ 工具链：

```sh
cargo install sloosh --locked
```

两个二进制通常都安装到 `$HOME/.cargo/bin`。crates.io 不包含 Tauri 桌面源码、
macOS 安装器或 DMG 打包资源，因此不能从 crate 构建 Sloosh DMG。此渠道适合 Rust
用户，不是免构建安装方式。

从仓库 checkout 构建时，见 README 中的
[源码构建步骤](../../README.md#从源码构建)。
安装完成后，继续阅读[使用手册](../manual.zh-CN.md)。
