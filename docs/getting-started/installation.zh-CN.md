# 安装

[English](installation.md) | 简体中文

GitHub Releases 是主要安装渠道，提供预编译二进制，用户无需 Rust 或 C 编译器。
crates.io 是为 Rust 用户准备的次要源码安装渠道，始终会在本机编译。

## 预编译二进制

从 [最新 Release](https://github.com/ReiSuzunami/sloosh/releases/latest) 下载：

| 平台 | 文件 |
|---|---|
| macOS 11 或更新版本，Apple silicon 或 Intel | `sloosh-macos-universal.tar.gz` |
| Linux x86_64，且 procfs 可读 | `sloosh-linux-x86_64-musl.tar.gz` |

同时下载 `SHA256SUMS`，安装前校验所选文件。

macOS：

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

macOS 二进制使用 ad-hoc 签名，目前没有 Developer ID 签名或 notarization。批准任何 OS
提示前先验证校验和。

Linux 二进制通过 musl 静态链接，以兼容常见 Linux 发行版。但 `sloosh` 仍需要 procfs
验证 peer executable 和进程 ancestry；静态链接不会消除这项运行时要求。其它 Linux
架构目前需要源码构建。

## 升级

替换二进制前先停止 daemon。活跃 session、forward、pending request 和 lease 都在内存中，
停止 daemon 后会丢失。

```sh
sloosh daemon stop
install -m 0755 sloosh-*/sloosh "$HOME/.local/bin/sloosh"
sloosh --version
```

这个顺序也避免 Linux 上旧 daemon 继续从已替换的 executable 运行；新 CLI 会拒绝无法通过
`/proc/<pid>/exe` 验证的 peer。

## 从 crates.io 安装

首次发布 crate 后，可通过此渠道下载源码并编译。需要 Rust 1.85 或更新版本，以及可用的
C/C++ 工具链：

```sh
cargo install sloosh --locked
```

二进制通常安装到 `$HOME/.cargo/bin`。此渠道适合 Rust 用户，不是免构建安装方式。

## 从 checkout 构建

```sh
git clone https://github.com/ReiSuzunami/sloosh
cd sloosh
cargo build --release --locked
```

生成的二进制位于 `target/release/sloosh`。
