# sloosh — ssh-in-the-loop 设计定案

面向 Coding Agent 的 SSH 操作工具。解决两个核心痛点：

1. **状态持久化**：Agent 的 shell 调用通常单次有效，跨调用丢失 cwd / 环境变量 / 后台任务；
2. **凭据隔离**：Agent 在不接触任何连接凭证的前提下操作远程主机，授权由人类带外批准（human-in-the-loop）。

命名：二进制 `sloosh`，repo `ssh-in-the-loop`（crates.io / Homebrew / GitHub 均已查证无撞车，2026-07）。

---

## 1. 架构总览

```
┌─────────────┐   spawn    ┌──────────────┐
│ Coding Agent│──────────▶ │ sloosh (CLI) │──── UDS / Named Pipe ───┐
└─────────────┘            └──────────────┘      NDJSON 协议        │
                                                                    ▼
┌─────────────┐            ┌──────────────┐            ┌────────────────────┐
│ 人类（另一个 │──────────▶ │ sloosh       │───────────▶│ sloosh daemon      │
│ 终端窗口）   │  approve   │ approve/add  │            │ · SSH 连接池 (russh)│
└─────────────┘            └──────────────┘            │ · 持久 PTY 会话     │
                                                       │ · vault（主密码加密）│
                                                       │ · 租约管理          │
                                                       │ · 审计日志          │
                                                       └────────────────────┘
```

- **接口形态**：CLI + Skill。理由：CLI 是 Agent 驾驭能力最强、零配置、可组合的接口；Skill 按需载入近零上下文成本。MCP 二期可作薄皮。
- **daemon 常驻、脱离 Agent 生命周期**：Agent 崩溃/重启不丢 SSH 状态，多 Agent 可共享连接。stdio 型 MCP Server 随 Agent 死亡，因此不采用。
- **单二进制**：daemon 即 `sloosh daemon run` 子命令；CLI 发现 socket 不可用时 fork 自身自动拉起（bind 原子性解并发竞态）。显式 `daemon start/stop/status` 留作调试。自动拉起不扩大攻击面——vault 仍锁、租约仍需人批。

## 2. 技术选型

| 组件 | 选择 | 决定性依据 |
|---|---|---|
| 语言/运行时 | Rust + tokio | russh 绑定 tokio；N 连接多路复用 + 定时器是 async 教科书场景 |
| SSH 协议 | **russh**（+ russh-sftp） | 程序化密码认证是一等公民（vault 取密码建连是核心流程）；openssh 二进制包装的密码认证只能靠 SSH_ASKPASS hack，排除；ssh2/libssh2 阻塞 + C 依赖 + 算法跟进慢 |
| 本地 IPC | 传输抽象 trait：Unix → UDS，Windows → Named Pipe | 鉴权模型依赖内核级 peer PID（`SO_PEERCRED` / `LOCAL_PEERPID` / `GetNamedPipeClientProcessId`）；TCP localhost 无可信对端识别，排除。Windows 的 AF_UNIX 无 Rust 生态支持且 peer creds 半文档化，用 Named Pipe |
| 线协议 | 换行分隔 JSON（serde） | 不需要性能、不需要 schema 编译、不放弃流式；`nc -U` 裸调试能力宝贵 |
| vault 加密 | argon2id 派生 + ChaCha20-Poly1305（AEAD） | 见 §4 |

- `~/.ssh/config`：支持常用指令子集（`Host` `HostName` `Port` `User` `IdentityFile` `ProxyJump` `IdentityAgent`），未知指令**警告而非静默忽略**。ssh-agent（含 1Password/Bitwarden 的 agent 实现）优先于 vault；`IdentityAgent` 可指定该 host 改用哪个 agent socket（或 `none` 关闭该 host 的 agent 认证）。`ProxyJump` 支持逗号分隔的多跳链，且任意一跳可以有自己的 `ProxyJump`（递归展开），总深度上限 8 跳，成环即报错拒绝。
- socket 路径：Linux `$XDG_RUNTIME_DIR/sloosh.sock`，macOS `~/.sloosh/sloosh.sock`，权限 0600。
- **平台纪律**：任何平台差异代码不许内联，必须进抽象层（IPC、进程树、文件权限、路径约定）。一期交付 macOS + Linux，Windows 二期填实现不动骨架。

## 3. 会话模型

- **Shell 级持久化**：每会话在远端维持一个长活 PTY shell。cwd、env、venv、后台任务跨调用延续。这是本工具的灵魂——连接级复用（ControlMaster 式）解决不了连续性痛点。
- **隐式寻址**：`sloosh run <host> "cmd"` 自动创建/复用该主机的默认会话；`--session <name>` 开同主机并行 shell（如一个挂 dev server、一个跑命令）。对 Agent 最好的簿记是没有簿记。
- **混合执行模型**：
  - `run` 默认阻塞（sentinel 切分输出与退出码），带超时；超时**不杀命令**，返回 `running` 状态 + 已有输出；
  - `peek`：**游标增量制**——默认只返回自上次 peek 以来的新增输出（对齐 Claude Code BashOutput 的模式，避免重复烧 token）；`--tail N` 显式回看；
  - `send`：向 PTY 发按键（应对交互式提示）；`interrupt`：发 Ctrl-C。
  - `run` 返回含明确状态字段：`done` / `running` / `dead`。
- **断线语义：报死不复活**。TCP 断开即远端 shell 死亡，daemon 如实报告 `dead` + 死因 + 遗言（最后的输出缓冲），由 Agent 决定重建。静默重建全新 shell 会让 Agent 在错误 cwd 里执行命令。远端 tmux 锚定的 `--resilient` 模式留二期，状态字段从第一天预留。
- **生命周期**：租约管访问不管会话存亡——租约过期不杀会话及其中进程，重新授权后原样接回。会话独立空闲回收（默认 8h 无读写断开，可配）。

## 4. 授权模型（核心创新点）

### vault
- 主密码加密文件：argon2id 派生密钥 + ChaCha20-Poly1305。
- **凭据录入是人类专属交互操作**（`sloosh add`）：Agent 可调用的命令面只有别名引用，不存在接受明文凭据的参数入口——否则凭据经过 Agent 上下文，边界即破。
- 密码仅在建连瞬间入内存，`zeroize` 用毕即抹；日志与错误信息永不回显。
- vault 条目可选带 `jump` 字段（`sloosh add <alias> ... --jump <alias>`）：跳板机别名，可解析自 vault 或 `~/.ssh/config`，语法与 `~/.ssh/config` 的 `ProxyJump` 一致。非密钥字段，不参与 zeroize，`Debug` 输出无碍。
- 后期扩展（不改 vault 格式，只加 key-wrapping 后端）：Touch ID / Windows Hello 门控的解锁路径；OS Keychain。

### 带外授权流（device-code 式）
1. Agent：`sloosh request <host>...` —— 请求**必须声明目标主机**（按主机授权；全库解锁使人类批准退化为橡皮图章）；daemon 收到请求后，会展开每个目标主机的 `ProxyJump` 链（vault `jump` 字段和/或 `~/.ssh/config` `ProxyJump`，递归展开、同样受 8 跳上限约束），把链上每一跳都并入请求的主机集合（目标在前，跳板依次在后，去重）——人类看到并批准的是整条路径，而不只是最终目标；
2. daemon 生成请求 ID，CLI 输出一条完整授权命令（含 ID 与主机清单）；
3. 人类在**另一个终端**（本机新窗口或另开 SSH 登入）粘贴该命令、输入主密码 → 租约生效。全程纯终端，天然支持无头环境；首次连接的 host key 指纹确认也放在这一步（正好有人在场）；
4. 租约空闲超时自动失效/轮换；`request` 对已有覆盖该主机的有效租约幂等返回成功，Agent 无需自己记状态。
5. **链上 lease 覆盖**：建连时，每拨一跳前都会检查——若该跳的凭据来自 vault（即 vault 里有这个别名的条目），调用方必须对这一跳也持有有效租约，检查方式与目标主机完全一致；纯粹从 `~/.ssh/config` 解析出来的跳板（走的是环境用户自己的凭据）不需要租约。缺租约时报错是教学式的：`jump host 'bastion' is vault-backed and needs its own lease; run: sloosh request <target> bastion`。

### Agent 身份锚定
- **主路径：进程祖先链绑定**。daemon 经 peer credentials 取调用方 PID，向上遍历进程树找到顶层 Agent 进程，租约绑定 **(PID + 进程启动时间)**（防 PID 复用）。该进程的一切后代自动命中租约 → **subagent 零配置继承**；Agent 重启 = 新进程 = 重新授权（合理的安全语义，用户已确认接受）。Agent 上下文中零 token。
- **逃生舱：`SLOOSH_LEASE` 环境变量**（进程树断裂场景，如 detached 进程）。环境变量对子进程天然继承，语义与血缘一致。
- Windows 注意：父进程死后 PPID 悬空可能指向被复用的 PID，须用"子进程创建时间晚于父进程创建时间"校验链条。

### 审计日志
- `~/.sloosh/audit.jsonl`，daemon 独写、追加式；Agent **可读**（回看自己操作史是正当需求，日志无凭据）。
- 记录：鉴权事件（请求/批准/过期，含 Agent 身份与主机范围）、连接事件（建立/断开/死因）、操作事件（每条 `run` 完整命令文本 + 会话 + 时间戳 + 退出码；`put`/`get` 两端路径）。不记命令输出（spool 已有）。
- `sloosh log` 供人查看，可按主机/时间过滤。没有留痕，带外授权只是仪式感。

## 5. 输出处理

- PTY 固有代价（知情即可）：stdout/stderr 合流；输出混有 ANSI 转义。
- **源头减排**：持久 shell 初始化注入 `export NO_COLOR=1 TERM=dumb`；daemon 侧剥离 ANSI 兜底；`--raw` 保留原样。
- `run` 返回最多尾部 **~30k 字符**（对齐 Claude Code 的 BASH_MAX_OUTPUT_LENGTH 量级，可配），带截断标记与总字节数。
- **全量输出落盘 spool**：`~/.sloosh/spool/<session>/<seq>.log`，`run` 返回附路径——Agent 用 grep/tail 细查大输出，不过 socket、不进上下文。按时间/总量自动清理。相对 Claude Code 的增强：远端命令可能昂贵或不可重入，截断不等于丢失。
- 会话环形缓冲默认 256KB，供 `peek` 使用。
- `put`/`get` 走既有连接的 SFTP channel；**文件内容不过本地 socket**——CLI 只传路径，daemon 同用户直接读写磁盘。

## 6. 命令面

**一期**：

| 类别 | 命令 |
|---|---|
| 执行 | `run` `peek` `send` `interrupt` |
| 会话 | `open`（显式并行会话入口） `ls` `kill` |
| 鉴权 | `request`（Agent 侧） `approve`（人类侧） |
| 凭据 | `add` `rm`（人类专属，交互式） |
| 传输 | `put` `get` |
| 运维 | `status`（daemon/租约/会话总览，Agent 迷茫时的锚点） `daemon start/stop/run/status` `log` |

**二期（按序）**：`forward` 端口转发（需求大，一期完成后立即推进）→ Windows 支持 → `--resilient`（远端 tmux 锚定）→ MCP 薄皮 → 生物识别解锁 / OS Keychain / 1Password·Bitwarden agent 兼容性验证。

## 7. Skill 策略

- 主文件百行以内：工具是什么；心智模型三句话（会话是持久的 shell / 访问需要人类批准的租约 / 迷茫先跑 `sloosh status`）；最常用五条命令各一行示例。
- 固化的 Agent 行为规则：鉴权请求发出后把授权命令展示给用户并**停下等待**，不轮询刷屏；`run` 返回 `running` 用 `peek` 增量跟进，不重复 `run`；**永不向用户索要密码/密钥**——凭据录入由用户在工具里自行完成。
- 细节靠 `sloosh <cmd> --help` 渐进披露，Skill 不复制参数表，避免腐化。
- **错误信息即教学素材**：如租约缺失报错直接给出 `run \`sloosh request <host>\` and show the approval command to your user`。工具运行时自我解释，Skill 只管开场。

## 8. 模块划分（实现参考）

```
src/
  main.rs            # 入口：CLI 解析，daemon 子命令分流
  cli/               # clap 命令定义、client 侧逻辑、daemon 自动拉起
  proto.rs           # NDJSON 请求/响应/事件类型（serde）
  transport/         # IPC 抽象 trait；unix.rs (UDS)；windows.rs (Named Pipe, 二期)
  daemon/
    mod.rs           # accept loop、请求路由
    session.rs       # PTY 会话：sentinel 切分、环形缓冲、游标、spool
    ssh.rs           # russh 连接建立、ssh_config 子集解析、ProxyJump、known_hosts
    lease.rs         # 租约：进程祖先链锚定、env 逃生舱、空闲超时
    vault.rs         # argon2id + ChaCha20-Poly1305、zeroize
    audit.rs         # audit.jsonl 追加写
  procs/             # 进程树遍历抽象；macos.rs (sysctl)；linux.rs (/proc)
skills/sloosh/       # Agent Skill（SKILL.md，agentskills.io 标准，兼容 Claude Code / Codex 等；
                     # 经 ReiSuzunami/nerv 插件市场与 npx skills 分发）
```
