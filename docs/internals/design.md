# sloosh 设计意图与实现状态

本文保留中文设计意图和能力状态，不重复定义精确实现契约。各主题的唯一权威来源为：

- 组件边界与运行时行为：[`architecture.md`](architecture.md)
- 线协议与 framing：[`protocol.md`](protocol.md)
- 威胁模型与能力边界：[`../../SECURITY.md`](../../SECURITY.md)
- 用户行为与命令入口：[`../../README.md`](../../README.md)
- 开发和测试流程：[`../../CONTRIBUTING.md`](../../CONTRIBUTING.md)

代码或本文与上述 owner 文档不一致时，应先验证真实运行行为，再在同一变更中修正代码、
测试和对应 owner 文档。

## 目标

`sloosh` 面向需要连续 SSH 状态的 Coding Agent：

- daemon 维持远端 SSH 连接和 PTY shell，使 cwd、环境变量和后台进程跨 CLI 调用保留；
- 人类在独立终端批准按主机划分的 lease，Agent 不需要持有 vault 主密码或 SSH 密码；
- 本地文件访问留在 CLI，daemon 只持有远端 SFTP 句柄；
- ProxyJump、SFTP 和 forwarding 服从同一 daemon 端授权边界。

它不是同 UID 恶意代码的强隔离沙箱。这个限制以及其它非保证项由 `SECURITY.md` 定义。

## 状态

| 能力 | 状态 | 说明 |
|---|---|---|
| macOS/Linux CLI + daemon | 已实现 | protocol 1，经 UDS 通信 |
| 持久 PTY session | 已实现 | 不跨 daemon 重启 |
| SFTP put/get | 已实现 | streaming，无应用层总文件大小上限 |
| ProxyJump | 已实现 | 包含批准范围复核和 routed host-key probe |
| 本地 `-L` forward | 已实现 | listener 仅绑定 loopback |
| 远端 `-R` forward | 已实现 | 暴露范围受 sshd `GatewayPorts` 控制 |
| GitHub 预编译包 | 发布就绪 | macOS Universal、Linux x86_64 musl |
| crates.io 源码安装 | 发布就绪 | `cargo install` 会在用户机器编译 |
| Windows | 未来 | 需要 Named Pipe 和 PID reuse-safe ancestry |
| resilient remote tmux | 未来 | 当前 SSH 断线后 session 进入 dead |
| OS keychain/biometric | 未来 | 用于加强同 UID secret isolation |

## 约束

- protocol 1 仍处于首次正式发布前；只有不兼容 wire 变更才递增版本。
- daemon 是 host authority，CLI 检查不能替代 daemon 端授权。
- 普通用户发布渠道是 GitHub 预编译包；crates.io 是 Rust 用户的源码渠道。
- 任何能力状态变化必须同步更新本表和对应 owner 文档。
