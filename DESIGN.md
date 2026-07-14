# sloosh 设计与实现状态

本文描述当前代码的真实行为。安全边界见 [`SECURITY.md`](SECURITY.md)，线协议见
[`docs/PROTOCOL.md`](docs/PROTOCOL.md)，英文架构说明见
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

## 1. 目标与边界

`sloosh` 面向需要连续 SSH 状态的 Coding Agent：

- daemon 维持远端 SSH 连接和 PTY shell，使 cwd、环境变量和后台进程跨 CLI 调用保留。
- 人类在独立终端批准按主机划分的 lease。Agent 不需要持有 vault 主密码或 SSH 密码。
- 本地文件访问留在 CLI 进程；daemon 只持有远端 SFTP 文件句柄。
- 所有本地进程仍处于同一 OS 用户边界。它不是同 UID 恶意代码的强隔离沙箱。

当前支持 macOS 和 Linux。Windows Named Pipe 与 Windows 进程树实现尚未提供。

## 2. 组件与数据所有权

```text
Coding Agent / human terminal
             |
             v
+----------------------- sloosh CLI -----------------------+
| arguments, TTY prompts, protocol check, local file I/O  |
| temporary approval-time vault read and host-key probes  |
+--------------------------+-------------------------------+
                           |
                           | Unix domain socket
                           | NDJSON control + raw frames
                           v
+---------------------- sloosh daemon ---------------------+
| peer PID, lease state, vault writer/cache, audit         |
| SSH connections, PTY sessions, spool, remote SFTP       |
| local and remote port forwards                          |
+--------------------------+-------------------------------+
                           |
                           v
                    SSH / SFTP servers
```

CLI 和 daemon 是同一个二进制的不同子命令。普通 CLI 请求会连接常驻 daemon；若 socket
不存在，CLI 自动启动 `sloosh daemon run`。daemon 重启会终止会话、forward、pending
request 和 active lease。

## 3. 本地传输与 protocol 1

当前线协议版本是 `1`。项目仍处于首次正式发布前，版本只在发生不兼容 wire 变更时递增：

- 控制消息为单行 NDJSON，包含结尾换行后最大 1 MiB。
- `Put`/`Get` 在 `TransferReady` 后切换为 raw frame。
- raw frame 为 4-byte big-endian `u32` 长度，加对应字节；长度 `0` 表示流结束。
- 单个 raw frame 最大 1 MiB；一个流可包含任意数量 frame，所以协议不限制文件总大小。
- 普通 CLI 先发送 `Status` 并要求 `wire_protocol == 1`，再发送
  `Hello { wire_protocol: 1 }`；daemon 回复 `ProtocolReady { wire_protocol: 1 }` 后，该连接
  才能发送普通请求。
- daemon 对每条连接维护协商状态。协商前仅允许 `Status`、`Hello`、`Shutdown`；其他请求
  在任何请求级副作用前返回错误。错误版本的 `Hello` 不会打开门禁。

NDJSON 控制部分仍可人工查看，但 `nc -U` 不能代表完整客户端：它不执行 daemon 身份
校验，也不会自动完成 `Status`/`Hello` 门禁、raw framing 或传输状态机。协议不是“所有
功能都能用一行 nc 调试”的接口。

CLI 连接后验证 socket 对端 eUID 与当前 `sloosh` 的 canonical executable path。daemon
通过内核 peer credentials 获取客户端 PID。该校验减少误连和简单 socket 冒充，但不解决
同 UID 进程注入、同路径二进制替换或进程调试。

## 4. Lease 与批准流程

### 4.1 请求和身份锚定

`sloosh request <host>...` 创建 pending request。daemon 从 UDS peer PID 向上遍历进程树，
选择一个 `(PID, process start time)` anchor。后续调用只要 ancestry 中包含该同一进程实例，
即可继承 lease；PID start time 保留内核提供的亚秒精度（Linux clock tick、macOS
`timeval` microsecond），避免把内核时间戳不同的同秒 PID 复用误认成原进程。
`SLOOSH_LEASE` token 是进程树断裂时的 bearer-token 逃生路径。

Lease 范围是主机别名集合，不是命令级权限。对一个 host 的 lease 可用于该 host 上的
session 操作、SFTP 和当前允许的 forward。

### 4.2 ProxyJump 的 fail-closed 批准

批准分两次独立解析：

1. request 时 daemon 展开当时可见的 `ProxyJump` 链并建立 pending request。
2. 人类 CLI 提示主密码，在自己的短期 vault cache 中重新展开完整链，显示精确 host 列表并
   要求人类确认。
3. CLI 发送 `ApproveLease { approved_hosts, ... }`。
4. daemon 用同一主密码解锁自己的 vault cache，再独立展开一次。
5. 两个有序列表必须完全相同；否则拒绝激活，pending request 保留。

此流程覆盖 request 时 vault 尚锁定、vault-only jump 尚不可见的情况。连接时，每个使用
vault 凭据的 jump alias 仍会再次检查 lease。

首次 host key 确认按依赖顺序执行：先 jump，再 target。后续 target probe 通过已经验证并
认证的 jump route 建立 `direct-tcpip`。未知最终 target 只完成 key exchange 以读取 key，
不会认证；人类确认 fingerprint 后才写入 `~/.sloosh/known_hosts`。拒绝或 probe 失败不会
自动信任，实际 SSH 连接继续 fail closed。

### 4.3 生命周期

- pending request: 15 分钟后过期。
- active lease idle timeout: 2 小时。命中的真实操作刷新 idle clock。
- active lease absolute lifetime: 8 小时。持续使用也不能延长。
- lease reaper: 每 60 秒扫描一次；API 调用也会先同步 prune。
- 最后一个 lease 消失后，daemon 清空并 zeroize vault cache。后台扫描带来最多约 60 秒的
  空闲检测粒度；新的 API 调用会更早触发清理。

长活任务不保存短命 CLI PID。创建 forward 时，daemon 将已解析授权转换为不透明
`LeaseGrant`，内部绑定 lease token 与单个 host。真实 forward 流量刷新 grant；15 秒
forward reaper 使用不刷新 idle clock 的检查，lease 失效后停止 listener 和已有 tunnel。

Lease 过期不会杀死 PTY session 或远端命令；它只阻止新的访问。重新批准后可接回仍存活
的 session。

SFTP transfer 也是一次在开始时授权的有限操作。daemon 在打开远端 SFTP handle、发送
`TransferReady` 前完成 lease 检查；进入 raw stream 后沿用该开始授权。即使 2h idle 或
8h absolute 边界在传输中到达，当前 transfer 仍可完成，新 transfer 则被拒绝。这样 NAS
大文件不会因 lease 时长变成隐含大小上限。

## 5. Session、输出与 spool

- 每个 `(host, session)` 持有一个远端 PTY shell。
- `run` 用随机 sentinel 在 PTY 合流字节流中识别命令结束和 exit code。
- timeout 返回 `running`，不杀远端命令。`peek` 使用共享 cursor；`send` 写按键；
  `interrupt` 发 Ctrl-C 并用 resync sentinel 防止 session 永久卡在 busy。
- SSH 断开后 session 标记 `dead`，不会静默创建一个 cwd 不同的新 shell。
- session 连续 8 小时无读写会被回收；session reaper 每 5 分钟扫描。
- 内存 ring 每 session 256 KiB。`run` 回复最多保留约 30,000 字符尾部。

Spool 是有界诊断保留，不是全量归档：

- 每个 run 的 spool 文件最大 64 MiB raw output。达到上限后写入明确 marker，后续输出不再
  落盘，但 sentinel 解析、远端命令和内存 ring 继续工作。
- 每个 session spool 目录保留预算为 64 MiB。run 结束时按最旧文件优先做 best-effort
  清理，活跃文件不会被删除。
- 整个 spool root 跨所有 host/session 有 1 GiB 硬预算，按实际已写入字节记账。active run
  不预留尚未使用的 64 MiB，因此空输出或小输出 run 不会制造虚假占用，也没有 16 run
  的并发上限。
- daemon 对每个 spool root 首次使用时做一次 lazy 索引，之后随写入增量维护账本；不会在
  每次 run 起止时全树扫描。索引不完整时暂停新的 spool 写入并在 30 秒后重试，不会让
  run 返回失败。需要为真实输出腾空间时，跨 session 按修改时间删除最旧的非活跃文件。
- 清理失败会记录警告，并可能使达到预算后的后续输出停止落盘；错误不向 run 传播，也不会
  删除活跃 spool，后续记账轮次会重试。当前 append/淘汰仍是同步文件系统调用，因此慢速
  spool 文件系统在预算压力下可能暂时拖慢 PTY reader；它已不再触发每次 run 的全树扫描。
- run 文件用 `create_new` 创建；session 重建或 daemon 重启后若序号重用，会改用带随机后缀
  的唯一文件名，绝不 truncate 已保留历史。
- host/session 名称编码为单一安全路径组件，避免目录穿越。
- spool 目录为 0700，文件为 0600，并以 `O_NOFOLLOW` 打开。

因此回复中的 `spool_path` 只表示“已保留输出”，不能承诺包含无限远端输出。
这些预算只约束 PTY command output spool，绝不限制 SFTP 文件大小或传输时长。

## 6. SFTP 传输

`put`/`get` 在既有 SSH 连接上新开 SFTP subsystem channel。文件总大小没有应用层上限；
实际限制来自本地/远端文件系统、网络和进程资源。
`russh-sftp` 默认的单请求 10 秒 timeout 已替换为锁定 Tokio 版本的 far-future deadline
（约 30 年）。这对 NAS 的 open/read/write/close 等同于无实际时限，但不是数学意义的无限；
真实 SSH、服务端、文件系统或网络故障仍会结束传输。

授权只在操作开始时检查。只有远端 SFTP handle 已成功打开，daemon 才发送
`TransferReady`；此后该 in-flight transfer 不再重新计算授权状态。Lease 过期只阻止后续
`put`/`get`，不截断当前大文件。

### Put

- CLI 解析并打开本地 regular file，然后逐个 1 MiB 以内 raw frame 发送。
- daemon 收到的 `local_path` 仅用于显示和审计，绝不据此打开本地路径。
- daemon 打开远端文件为 create + truncate + write，并逐 frame 写入。
- 中断或远端错误可能留下已截断或部分写入的远端文件。当前无 resume 或远端原子替换。

### Get

- daemon 从远端 SFTP 文件读取并逐 frame 发给 CLI。
- CLI 在目标目录以请求 mode `0666` 创建临时文件，由调用进程的 umask 原子决定实际权限。
  只有收到 raw EOF 和最终 `Transfer` 成功响应后，才原子提交到目标路径。
- 默认拒绝覆盖；`--force` 使用同目录 rename 替换。失败时既有目标保持不变；异常进程
  终止可能留下未提交 temp 文件。

## 7. Forward

当前实现：

- `-L [bind_addr:]local_port:remote_host:remote_port`。
- bind address 必须是 loopback IP；省略时为 `127.0.0.1`。`0` 可请求 OS 分配监听端口。
- `-R [bind_addr:]remote_port:local_host:local_port`。远端 listener 由 SSH server 创建；
  `remote_port = 0` 可请求 server 分配端口。
- 每个 forward 使用专用 SSH connection 和稳定 `LeaseGrant`。
- `-R` 的每个入站连接都会重新验证并刷新该 grant，然后才连接本地 target。`GatewayPorts`
  等 sshd 配置决定远端 bind address 是否对外可达。
- `-R` route 使用单调 `Pending -> Active -> Closed` 状态；只有 server 已确认 listener 且
  registry 已就绪后才进入 Active。Pending/Closed 的入站 channel 直接拒绝。
- 本地 target connect 最长等待 10 秒，并与 Closed 状态竞速；accept 前再次检查 state 与
  grant。stop/expiry 先切 Closed，再最多等待 2 秒取消远端 listener，之后无论 server 是否
  回复都释放专用 SSH connection。
- `forward ls` 只读，`forward stop` 只减少访问，因此不要求 lease。

当前禁用：

- 非 loopback `-L` 始终拒绝。

`-R` 当前复用“主机可访问”lease；这是显式产品边界，调用者必须把远端 listener 视为
主动网络暴露，而不是本地 `-L` 的等价形式。

## 8. Vault、状态文件与审计

Vault 使用 Argon2id 派生 32-byte key，再用 ChaCha20-Poly1305 加密 versioned JSON envelope。
每次保存使用新 salt 和 nonce。daemon 是 vault mutation 的唯一正常写入者：add/rm 的完整
read-modify-write 与 cache refresh 串行化，文件通过 0600 临时文件和 atomic rename 替换。

`unlock_for_lease` 与 add/rm mutation 共用同一把 async mutation lock，因此 unlock 不会与
写入或 cache refresh 交错。Unlock 只读取一个 `VaultFile` envelope，并从该同一快照的
KDF 参数派生 key、解密同一快照的 nonce/ciphertext，再一次性发布 cache；不会混合两次
文件读取，也不会让旧 unlock cache 回写覆盖较新的 mutation。

至少一个 lease 存活时，daemon 缓存解密后的 vault 数据与派生 key。批准 CLI 也会短暂
建立自己的只读 cache，用于完整 ProxyJump preview 和 routed host-key probe；流程结束必定
清空。

`~/.sloosh` 与平台 fallback runtime dir 等 sloosh 自有目录创建/修复为 0700，拒绝
symlink、错误 owner 和非目录。`SLOOSH_SOCKET` 指向非默认父目录时只做安全校验：目录必须
已由当前 eUID 拥有且 mode 为 0700；macOS 上还必须无扩展 ACL。daemon 不会 chmod 或清理
该目录的 ACL。
socket、vault、daemon log、audit、known_hosts 与 spool 文件目标权限为 0600；不同文件
使用的 `O_NOFOLLOW`、`create_new` 和 ACL 清理细节见 `SECURITY.md`。

Audit 是 best-effort 诊断记录，不是防篡改安全控制。它记录授权、连接、命令文本、路径和
结果元数据，不记录命令输出；同 UID owner 可读取、删除或替换它。

## 9. 状态矩阵与后续工作

| 能力 | 当前状态 | 当前边界 |
|---|---|---|
| macOS/Linux UDS | 已实现 | protocol 1，CLI peer 校验 + Status/Hello 双向门禁 |
| 持久 PTY session | 已实现 | 8h idle 回收，不跨 daemon 重启 |
| SFTP put/get | 已实现 | 单 frame 1 MiB，总量不限；开始时授权不截断当前大文件 |
| Spool | 已实现 | 64 MiB/run，64 MiB/session，1 GiB/root；仅约束 PTY output |
| ProxyJump | 已实现 | 递归最多 8 hop；批准列表双重解析；routed key probe |
| `-L` forward | 已实现 | 仅 loopback listener |
| `-R` forward | 已实现 | 远端 listener；稳定 grant；暴露范围受 sshd `GatewayPorts` 影响 |
| 非 loopback `-L` | 禁用 | 等 capability-specific approval |
| Windows | 未来 | Named Pipe + PID reuse-safe ancestry |
| resilient remote tmux | 未来 | 当前断线只报告 dead |
| OS keychain/biometric | 未来 | 用于加强同 UID secret isolation |
| MCP 薄层 | 未来 | CLI 仍是当前唯一正式接口 |
