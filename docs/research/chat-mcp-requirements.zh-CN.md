# Chat MCP 需求

> 非权威规划记录，不定义已发布行为。
> 已发布权威仍是 [`SECURITY.md`](../../SECURITY.md)、
> [`architecture.md`](../internals/architecture.md)、
> [`protocol.md`](../internals/protocol.md)。
> 英文原文：[`chat-mcp-requirements.md`](chat-mcp-requirements.md)。
> 相关调研：[`cloud-mcp-ssh-research.md`](cloud-mcp-ssh-research.md)。

状态：2026-08-19 产品讨论达成的需求草案。
落地时须在同一变更里更新合同、测试、帮助、译本和 Skill。
除非出现具体的不兼容 schema / 帧 / 默认值 / 时序变化，导线协议保持版本 3。

## 1. 问题

ChatGPT 与 Claude Chat 不能拉起本机 `stdio` MCP。它们的 Connector 由厂商云出站访问远程 Streamable HTTP。

市面默认——公网 `/mcp`，网关持有 SSH 钥匙或密码——会把主机权威挪出本机。这与 sloosh 冲突：daemon 是权威；租约绑 PID+启动时间；带外批准不能来自请求进程树；vault 密码、SSH 秘密、lease token 不得离机。

Chat 用户也没有本机 TTY。逐条 `sloosh approve` 做不成 Chat 体验。

## 2. 要达到的结果

人把 sloosh 装在**想被 Chat 操作的那台机器**上。本机显式开通后，Chat 操作这台机器不再弹窗。同一开通可以把已经符合现有 system-agent-only 自动租约的远端主机加进名单。在这些目标上，Chat 对已授权工具无监督执行（YOLO）。云端不当 SSH 客户端，也不持有 vault。

## 3. 非目标

- 把 `slooshd` 暴露成公网 Streamable HTTP MCP。
- 托管 SSH 网关代存钥匙、密码或 `SLOOSH_LEASE`。
- 把 MCP OAuth 或 MCP session id 当成主机租约。
- 主机开通后再做逐条或对话内批准。
- 自动纳入密码、key-file、自定义 Agent 或带 `IdentityFile` 的主机。
- 让 Chat 自动信任未知或变更的 host key。
- 默认 YOLO 包含远端转发（`-R`）。
- 给桌面 Cursor / Claude Code / Codex 新开本机 exec API。那些客户端已有本机壳，继续走 CLI + Skill。
- 把 Anthropic MCP Tunnels 写成 claude.ai Connector 路径。Console 隧道目前不能当 Claude Chat Connector。

## 4. 角色

| 角色 | 在哪 | 可以 | 不可以 |
|---|---|---|---|
| 人类 | 安装机 | 开通 Chat、点 allowlist、启停桥、撤销 | 把 vault 密码、钥匙、lease token 贴进 Chat |
| ChatGPT / Claude 云 | 厂商 | 当 MCP 客户端，打中继 | 看见 vault、钥匙、`SLOOSH_LEASE`、daemon socket |
| 中继 / 隧道边缘 | 厂商隧道或自建出站汇聚 | 绑定 Chat 用户 ↔ 桥实例，转发 MCP 帧 | 解密 vault、自己 SSH、签发或持有主机租约 |
| `sloosh-bridge` | 安装机上与人类同 UID | 出站；把 typed MCP 工具翻成协议 3 | 批准租约、打开调用方指定的本地路径 |
| `slooshd` | 安装机 | 权威：Chat 授权、SSH、PTY、远端 SFTP 句柄 | 对外听 443 |

OAuth 只证明这个 Chat 账号绑过这台桥。主机能力仍是 daemon 的 grant。

## 5. 架构

```text
Chat  -- MCP + OAuth -->  中继  -- 已建立的出站隧道 -->  bridge
                                                           |
                                                           | Unix socket
                                                           | Status → Hello → ProtocolReady
                                                           v
                                                        slooshd
                                                           |
                                       +-------------------+-------------------+
                                       |                                       |
                                       v                                       v
                             local（不走 SSH）                      allowlist 里的 SSH 主机
```

规则：

- Chat 永不直连 `slooshd`。安装机只出站。
- 协议 3 仍是本机 IPC。桥是现有 daemon 的新客户端，不是新导线版本。
- 适配层不得改变授权顺序、传输上限、原子下载语义。
- `integration-test-hooks` 保持仅测试，不得出现在 CLI 或 MCP。

## 6. 一等目标

### 6.1 `local`（Chat 第一用途）

Chat 的第一目标是**跑着 sloosh 的那台机器**，不是远端 SSH 主机。

- 稳定身份：`local`（或文档规定的本机主机名 alias）。
- 执行：daemon 持有的、用户 UID 下的持久 shell。session、cwd、环境、后台任务跨 Chat 轮次存活，对齐现在的远端会话模型。
- `local` 不需要 sshd、host key、ssh-agent。
- 对该 daemon 开通 Chat，就是 `local` 的全部用户鉴权。
- `local` 只给 Chat audience。普通 CLI / 桌面不借此获得通用本机 exec API。

### 6.2 远端 SSH（第二用途）

可选，来自现有主机清单的具名 alias。

远端主机进入 Chat allowlist 必须同时满足，并且**每次使用 grant 都复检**：

- 精确目标与每一跳 ProxyJump 都只用默认 `$SSH_AUTH_SOCK` 或 vault `Agent` profile；
- 没有 `IdentityFile`、自定义 `IdentityAgent`、密码、key-file；
- 每一跳的 key 已在 `~/.sloosh/known_hosts`；
- daemon 能权威验明范围（已解锁 vault，或可证明的 OpenSSH 配置纯 Agent 路径）。

仅 CLI 的冷加密 vault 仍不能把「读不到」当成「是 Agent」。此时 Chat **拒绝**该主机，而不是挂起等 TTY 批准。

主机后来离开该策略，Chat 访问立即 fail-closed。

## 7. 开通是 Chat 唯一的用户鉴权

Chat 没有批准面。对话里没有 `sloosh approve`，也没有密码框。

本机一次显式动作打开 Chat，例如 `sloosh chat enable` 和/或桌面开关。该动作：

- 启动或要求出站桥已在；
- 始终提供 `local`；
- 可追加具名的 system-agent-only allowlist；
- 在 daemon 记下 audience `chat`。

开通之后，Chat 不再为这些目标做用户鉴权。改 allowlist、关闭 Chat、停桥，都是另一次本机显式动作。

桌面 Agent 的租约不变。密码、key-file、自定义 Agent 在 CLI/桌面路径上仍走今天的带外人类批准。

## 8. YOLO

YOLO 是把现有租约规则用在 Chat audience 上的名字：host grant 是能力，不是命令意图。daemon 不检查 shell 是否安全。

Chat 已对某目标开通且 Chat grant 仍活着时：

- 该目标上的 `run` / `peek` / `send` / `interrupt` / 开停 session 不再弹窗；
- 该目标上的 SFTP 仍遵守现有起始时刻租约和原子 `get`；
- 仅 loopback 的本机转发（`-L`）可作为 typed tool。

YOLO **不包含**：

| 动作 | 原因 |
|---|---|
| allowlist 外的主机 | 新的主机能力 |
| 密码、key-file、自定义 Agent、`IdentityFile` | 扩大凭据权威 |
| 未知或变更的 host key | 这是信任，不是用户鉴权；Chat 不能确认指纹 |
| 远端转发（`-R`） | 额外的故意暴露 |
| 把 idle 拉成永远 | YOLO 是「不问命令」，不是「永不收回」 |
| 让 Chat 自己扩围 | 开通必须留在本机人类侧 |

idle 使用现有共享 vault 超时（1 / 5 / 15 / 30 分钟）以及 daemon 的 8 小时硬顶。活动可按现有 grant 检查刷新空闲钟。过期后目标不可用，直到 Chat 仍 enable 且能再发自动 grant；**不会**在 Chat 里弹批准。

过期后的 PTY 按现状：会话可在但不可用，直到有活 grant。已过 `TransferReady` 的 SFTP 可完成；新操作失败。

## 9. Chat 的 typed 工具

MCP 只暴露编译过的工具，不是裸协议 3，也不是 `sloosh` 命令行。

最小集合：

| 工具 | 目标 | 说明 |
|---|---|---|
| `run` | `local` 或 allowlist 主机 | 持久 session；有界回复 + spool |
| `peek` | 同上 | 增量输出 |
| `interrupt` / `kill` | 同上 | 只减权限 |
| `sftp_get` / `sftp_put` | 同上 | CLI/桥打开本地路径；daemon 把 `local_path` 当标签；`get` 同目录 `create_new` 再原子提交 |
| `forward_local` | allowlist 里的 SSH 主机 | 只绑 loopback |

不要暴露：任意 daemon 消息、`-R`、主机清单改写、vault 解锁、`host trust`、Skill 安装。

PTY 环、回复、spool、session、root 预算必须与 `SECURITY.md` 完全一致。

## 10. 流程

### 10.1 一次性开通

1. 人在 Chat 要管的机器上安装 sloosh 并完成 `sloosh init`。
2. 人开通 Chat，可选点名远端 agent-only 主机。
3. daemon 记下 audience `chat`。`local` 可进。远端名字仅在仍符合 §6.2 时准入。
4. 桥校验 daemon（eUID + 规范 `slooshd` 路径），走完 `Status → Hello → ProtocolReady`，出站连中继。
5. 人在 ChatGPT 和/或 Claude 添加 Connector（中继 URL 或官方隧道身份），做完厂商 OAuth。
6. 中继保存 Chat 用户 U ↔ 桥实例 B。除 enable 外还没有主机租约。

### 10.2 日常命令

1. Chat `tools/call` `run`，目标是 `local` 或 allowlist 主机。
2. 中继只接受绑到 B 的有效 OAuth，转发帧。
3. 桥向 daemon 要该精确范围的 Chat grant。
4. 策略仍成立则 daemon 自动发方法受限 grant；否则给 Chat **类型化拒绝**，不挂 TTY pending。
5. 桥发已有的 `Run`（或等价请求）。
6. 有界输出回到 Chat。秘密不进日志。

### 10.3 撤销（两层都要）

| 人的动作 | 效果 |
|---|---|
| 断开 Chat OAuth / 去掉 Connector | 中继不再转发；本机 grant 可能还在 |
| 关闭 Chat / 从 allowlist 去掉主机 / Chat grant idle | daemon 拒 `Run`；OAuth 可能还有效 |
| 停桥或断出站 | Chat 调不了工具 |
| `sloosh daemon stop` | 会话、转发、grant 全没，与现在相同 |

Chat OAuth 过期 ≠ 主机 grant 过期。两边都要活着。

## 11. 中继选型（未决）

本机授权模型相同，只是 Chat 怎么找到桥不同。

| 方案 | ChatGPT | Claude Chat | 说明 |
|---|---|---|---|
| A. OpenAI Secure MCP Tunnel | 官方出站 | 无 | 除非再补一条，否则只有 ChatGPT |
| B. 自建出站汇聚，对外 `/mcp` | Connector URL | Connector URL | 两边都能用；汇聚点仍不持 vault |
| C. A + B | 都有 | 都有 | 同一座桥，两个边缘 |

在厂商把 Anthropic MCP Tunnels 开放给 Chat Connector 之前，不把它算进路径。

实现前在 A、B 里选定。不要因为这个选择卡住 `local` + YOLO。

## 12. 不得移动的安全不变量

- daemon 仍是权威。Chat grant 是新 audience，不替代 CLI/桌面的 PID+启动时间或 `SLOOSH_LEASE`。
- lease token 永不回到 Chat、中继或厂商云。
- 永不传递或记录 vault 密码、SSH 密码、私钥、交互 `send` 内容、解密后的 vault 数据。
- CLI/桌面仍需人类批准时，批准不能来自请求进程树。Chat 开通是另一条本机人类控制，不是模型带内批准。
- host-key 不匹配 fail-closed。Chat 不是信任 UI。
- 本机转发只绑 loopback。
- 只有 CLI/桥打开 SFTP 本地路径。
- 资源上限保持 `SECURITY.md` 所载。
- 自动 grant 保持方法受限；脚下认证方式被改则 fail-closed。

新增威胁：提示注入或被盗的 Chat OAuth，得到安装机上该 UID 的壳（`local`），以及 allowlist SSH 主机上的 YOLO。同 UID 本地恶意进程本就在强边界外；新的调用方在厂商云。因此 enable 必须显式、默认关、且能不经过 Chat 就撤销。

## 13. 验收

必须做到：

1. Chat 未开通时，厂商云不能在这台机器上跑任何东西。
2. 只开通、不加远端 allowlist 时，Chat 只能对 `local` 做 `run`/`peek`，且跨轮次保持 session。
3. 开通时点名的、已知 key 的 system-agent-only 主机，对 Chat 是 YOLO。
4. 密码、key-file、自定义 Agent、`IdentityFile`、未知 key 主机被 Chat 以类型化错误拒绝，不挂 pending approve。
5. 主机改出 agent-only 或 host key 变更，立即取消 Chat 访问。
6. `slooshd` 无公网监听。截获中继流量看不到 vault 材料和 lease token。
7. 协议 3 仍是 3；不匹配 / 升级测试仍成立。
8. 桌面/CLI 的 key-file 与密码主机仍要今天的批准。
9. 默认 YOLO 拒绝 `-R`。
10. 断开 OAuth 或关闭 Chat，都能独立挡住新操作。
11. Chat 发起的 run 仍受 PTY/回复/spool 上限约束。
12. `get` 仍同目录 `create_new` 再原子提交；daemon 仍不打开调用方指定的本地路径。

## 14. 真正落地时的文档归属

| 归属 | 更新 |
|---|---|
| README + `--help` + 译本 | Chat 开通、`local`、YOLO 范围 |
| `SECURITY.md` | Chat audience、`local` exec、云调用方威胁 |
| `architecture.md` | 桥、中继、`local` 与 SSH |
| `protocol.md` | 仅当消息或时序变化（然后升版本） |
| `SKILL.md` | Chat 不是桌面 Agent 路径 |
| `cloud-mcp-ssh-research.md` | 指向本需求记录 |

不要把精确数字上限抄进使用手册。
