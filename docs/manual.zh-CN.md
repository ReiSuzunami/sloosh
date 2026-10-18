# Sloosh 使用手册

## Dangerous Bypass Mode

### bypass 模式下解锁凭据

macOS 的 Dangerous Bypass Mode 自动解锁，复用通过 Touch ID 或 PIN 登记的
现有 Sloosh Keychain 凭据。开启 bypass 意味着同一系统
用户下的所有客户端在 daemon 重启或缓存过期后仍可无人值守使用 vault 凭据。
无需第二个开关；自动解锁与 bypass 一起在下次 daemon 启动生效。
连接／路由解析遇到冷缓存时，静默读取 Keychain 并验证当前 vault；不另存密码。
Keychain 无法读取或凭据已失效时直接报具体错误，不弹窗、不退回主机审批。
缓存时限保留，但下一次连接可以重新自动解锁。正常模式及桌面管理页认证不变。

未安装内置 helper 或没有可用 Keychain 凭据时，可以主动在桌面 Hosts 页面解锁，
或自行运行 `sloosh host list`；daemon 不会自行弹出备用解锁窗口。
成功的新增、编辑、删除、列举与 vault 初始化，也会向
bypass daemon 发布已验证凭据。首次新增可以早于任何 lease，无需再次 approve/trust。
空闲时限复用超时设置，绝对上限为缓存创建后 8 小时；普通读取不重置绝对上限。
daemon 不保存主密码；错误密码不会解锁缓存。

vault 锁定时无法判断别名是否存在，目标与跳板在联网前明确报错，不尝试其他地址。
bypass 自动解锁失败时返回具体的 Keychain 错误。
即使主机只存在 SSH 配置，也须先解锁已有 vault；确认不存在的条目仍正常透传 SSH
配置／系统 Agent。已建立的 SSH 会话保持原连接；编辑影响新连接，新连接始终使用
同一份地址、用户名、路由和认证快照。
桌面管理页锁定不撤销 daemon 的租约或 bypass 缓存；需要立即终止时停止 daemon。



仅在接受同一系统用户的客户端全访问、首次连接可能信任攻击者的风险时开启。
使用 CLI 实际选择的 `slooshd`：命令行安装通常选同目录 helper，macOS 已安装 App
时可能优先选 App 内 helper。先停现有 daemon（会终止会话与转发），另开终端启动：

```sh
sloosh daemon stop
/path/to/selected/slooshd --dangerous-bypass-mode
```

保持运行，直接使用 `run`、`put`、`get` 或 `forward`：无需申请 lease、主机范围授权、
token 或续约。`sloosh request myhost` 可选，仅检查路由与 vault 就绪状态，不创建 lease。
无需 approve 弹窗或终端确认；未知目标与跳板主机密钥自动保存，已知密钥变更仍拒绝。
SSH 登录凭据与加密 vault 解锁仍必需；缓存过期后尝试 Keychain 自动解锁，而非续约 lease。
启动和兼容请求可通过 `sloosh log` 查看；首次信任会在 daemon 输出警告。
它不是单次调用参数。

持久开启：桌面端 **Security → Dangerous Bypass Mode → Enable on next start**，
确认风险后保存。GUI 不会中断当前 daemon；准备好后停止并重新启动 daemon。
停止会丢失会话、转发和 lease。之后 CLI 与桌面自动启动均读取已保存策略。

共享配置为 `~/.sloosh/vault-settings.json`（设置 `SLOOSH_HOME` 时位于该目录）。
保留原有超时值，加入配置：

```json
{"version":1,"idle_timeout_minutes":15,"dangerous_bypass_mode":true}
```

文件必须仅当前用户可读写（`0600`）。文件或字段缺失默认关闭；配置损坏或权限
不安全会拒绝启动。参数会覆盖配置中的 false 而开启，但不会修改持久配置。

关闭：GUI 选择 **Disable on next start**（或将配置字段改为 false），停止 daemon，
不带参数重新启动。
此前自动保存的主机信任仍保留；关闭模式不会撤销已保存的信任。


[English](manual.md) | 简体中文

本手册面向人类用户，介绍初始化与日常 CLI、桌面端操作。Agent 应遵循内嵌的
[Agent Skill](../skills/sloosh/SKILL.md)；安全保证与限制以
[SECURITY.md](../SECURITY.md) 为准。

## 初始化

请在人类自己的交互式终端中运行：

```sh
sloosh init
```

它会安装内嵌 Agent Skill 并初始化凭据 vault。仅命令行安装中，password、key-file 与
自定义 Agent scope 由人类在另一终端批准；仅使用默认系统 SSH Agent 的 scope 自动授权。
macOS 桌面 App 通过自身的 Setup 与 Security 配置 Keychain、Touch ID 与可选审批 PIN。

验证结果：

```sh
sloosh skill status --agent auto
sloosh status
```

Skill 检测区分缺失、当前版本、可更新、本地修改和外部管理。桌面 Setup 显示检测路径，
单独报告读取失败，窗口重新获得焦点时刷新。Codex 通用路径为 `~/.agents/skills/sloosh`，
Claude Code 使用 `~/.claude/skills/sloosh`；后者链接到共享目录时可正确识别，不重复写入。
更新不会沿软链接写入或覆盖自定义内容；需更新直接指向的受管理目录。

安装、校验和、升级与平台排障见[安装指南](getting-started/installation.zh-CN.md)。

## 配置主机

**系统托管只保留一份配置：** Hosts 无需解锁 vault，即可读取 `~/.ssh/config` 及
Include 文件中的明确主机别名。选择 System SSH 或系统托管密钥选项，只把连接配置
写入 SSH config；密钥选项执行 ssh-add 后丢弃粘贴内容，不创建 vault 副本。
不交给系统的密码／私钥仍可保存在 vault。系统中的明确别名优先于同名旧 vault 记录，
hostname 和 ProxyJump 均以系统为准；旧记录保留，不擅自迁移或删除。
通配符仅提供默认值，不列为主机。编辑／删除仅支持主配置文件内唯一、明确的 Host 段；
Include、共享或重复定义需修改源文件。其他设置和注释原样保留，存在优先级覆盖时拒绝写入。
`sloosh host add --auth agent` 同样直接写系统配置，无需初始化 vault。

列表一次只显示一个来源：**System SSH config / Sloosh vault** 切换器标注各来源主机数
（vault 锁定时显示锁标记），下方为所选来源的标题、解锁控件、空状态与主机行；
保存主机后自动切到其来源。新增时明确选择 **Save to**，编辑时来源固定，不做隐式迁移。
Vault 锁定时仍可选中，在添加窗口内解锁后继续保存，已填主机信息不会丢失。
系统来源中的文件／粘贴密钥在保存时执行 ssh-add；vault 来源的密钥保留在 vault。
解锁控件只放在 vault 来源。不可编辑条目提前显示原因；删除确认按来源说明实际操作。
主机保存成功但密钥加载失败时只显示一条警告，不同时出现成功和失败提示。

**Through saved host** 只显示与目标同来源的主机：系统目标只选系统 SSH 跳板，vault 目标只选 vault 跳板。
切换 **Save to** 会清空已选跳板。系统 SSH 别名保存为 ProxyJump，vault 主机保留 managed-host 路由。
路由只提供 **Direct** 和 **Through saved host**。已有 ProxyJump 配置只读显示，除非明确选择新路由，否则原样保留。

编辑、列出、删除和信任主机仍由人类操作。Agent 可无 TTY 执行
`sloosh host add`，只新增、不覆盖。需先初始化 vault：普通模式通过内嵌原生窗口
收取主密码；危险绕过模式读取已有 Keychain 凭据。SSH 密码也由用户在原生窗口
输入，Agent 不接触密码。未安装原生 helper 时，仍由人类在终端添加。
新增配置不授予连接租约，也不自动信任主机指纹。

```sh
sloosh host list
sloosh host show myhost
sloosh host add myhost --hostname server.example.com --user deploy --auth agent
sloosh host edit myhost --port 2222
sloosh host trust myhost
sloosh host rm myhost
```

认证方式包括 SSH agent、vault 加密密码、私钥文件路径，或在桌面主机编辑器中
粘贴私钥。粘贴内容加密保存在 vault，不写明文密钥文件，上限 256 KiB。未加密 Ed25519/ECDSA
直接签名；RSA 或加密 OpenSSH 私钥保留 KeyFile profile，同时由人类把同一把钥匙
载入 daemon 使用的 SSH Agent。Sloosh 只选择对应公钥身份，不解密钥匙，
也不在本地进行 RSA 签名。没有可读 OpenSSH 公钥元数据的加密格式不受支持。

Agent 缺少该身份时，错误会给出经过 shell 引号转义、指向 daemon 实际 Agent socket
的命令。请自行执行后重试；私钥口令只输入系统工具的人类提示中。服务器拒绝钥匙时，
应检查远端用户的 authorized_keys；加载其他钥匙不会改变此 profile 选中的身份。
KeyFile 的 lease 审批要求不变，Sloosh 不配置 Agent 重启后的自动加载。
SSH 配置主机保持现有 Agent 优先的认证顺序。

两种私钥输入均可勾选 **Load into system SSH Agent on save**：保存成功后执行一次
`ssh-add`。默认关闭，修改认证时需重新勾选。粘贴私钥只通过 stdin 传递，不进入参数、
环境变量或临时文件。App 的 `SSH_AUTH_SOCK` 必须与 daemon 一致；加密私钥需要已配置
`SSH_ASKPASS`，或由用户手动加载。使用同一 Agent 的其他应用也能使用该密钥。
加载失败会明确提示主机已保存并显示警告，不回滚配置；不修改登录或启动加载设置。

使用 `--auth agent` 的 vault profile 只使用默认系统 `$SSH_AUTH_SOCK`；daemon 能检查
已解锁 vault 后可跳过人工 lease 批准。DMG Keychain 预览可无审批弹窗提供该状态；仅 CLI
的冷启动 vault 仍会 pending，因为不能把加密 vault 中“看不到”误判成“不存在”。OpenSSH
配置主机只有在目标与完整 ProxyJump scope 都使用默认 Agent，且没有 `IdentityFile` 或
自定义 `IdentityAgent` 时才走相同自动路径。lease 仍绑定进程并受超时限制；主机离开该
策略后，自动 lease 会立即失效。

路由可以直连、经过另一条受管主机配置，或使用高级 OpenSSH ProxyJump：

```sh
sloosh host edit myhost --via bastion
sloosh host edit myhost --proxy-jump jump.example.com
sloosh host edit myhost --direct
```

alias 是稳定身份，不能改名。所有选项见 `sloosh host add --help` 与
`sloosh host edit --help`。

未存入 vault 的主机会回退到 OpenSSH 配置。Sloosh 支持 `Host`、`HostName`、
`Port`、`User`、`IdentityFile`、`ProxyJump` 与 `IdentityAgent`，也支持首个
`Host` 前的全局默认值。`Include` 支持嵌套文件、多个带引号路径、`~/` 展开与按
字典序加载的通配符；嵌套文件中的相对路径也以 `~/.ssh` 为基准。未匹配的路径
忽略，`Host` 条件作用域保持隔离。文件不可读、超出包含限制、动态 `%`/`$` 路径、
`~user` 与递归 `**` 通配符仍会拒绝解析，不会静默丢失连接设置。
其他 `Host` 块中的不支持指令保持静默；命中目标的低影响
未实现选项只生成一条精简诊断。已知会改变 endpoint、路由或 host-key 身份的
`ProxyCommand`、`ProxyUseFdpass` 与 hostname
canonicalization 会直接失败，不会猜测默认设置。Sloosh 不解析 `Match` 条件，
所以任何 `Match` 区段都会让 SSH-config-backed 主机 fail closed。直连 vault
profile 不读取无关 SSH 配置。

## 桌面 App

macOS DMG 包含 Sloosh 桌面控制面与私有 `slooshd`，不会安装公共 CLI。需要终端或
Agent 访问时，请另用 Homebrew、Cargo 或命令行压缩包安装 `sloosh`。App 位于
“应用程序”时，两个客户端会共用 App daemon 与状态；桌面端直接连接 daemon，不会
通过 shell 调用 CLI。

Setup 安装内嵌 Agent Skill 并初始化 vault；Security 配置 Touch ID、可选的 6 位
Sloosh PIN 与共用 Idle timeout（空闲超时）。启用 Touch ID 或 PIN 会把 vault Master
Password 的受保护副本存入 macOS login Keychain。若 macOS 询问，`Always Allow` 可避免
该项目的重复访问提示，`Allow` 只授权一次。这些操作不会导入 SSH 私钥，也不会授予 SSH 访问权限。

Hosts 管理与 CLI 相同的 vault 主机配置，可使用 Touch ID、Sloosh PIN 或 Master
Password 解锁。原生审批按钮显示 `Master Password (vault)`，指 vault 主密码而非 macOS
登录密码。PIN 提交按钮在桌面解锁时为 `Unlock`，SSH 审批时为 `Approve`。
Master Password 与 PIN 只在内置原生 helper 中输入，不会进入 WebView。
Hosts 中输入的 SSH password 仅短暂存在，通过本地命令边界时使用脱敏 secret，提交后
立即清空。Finder 隐藏 `.ssh` 时，可直接输入私钥完整路径，也可继续使用文件选择器。

每条主机记录只保留 **Test connection**。需要信任时弹窗显示实际解析的
endpoint、key algorithm 与 SHA256 指纹；key 发生变化时，同时显示旧、新指纹及其来源文件。
请通过独立来源核对新指纹，再选择 `Trust and continue` 或 `Replace and continue`。
Sloosh 写入前会重新解析路由并重新探测，
且只会修改 `~/.sloosh/known_hosts`，绝不修改 `~/.ssh/known_hosts`。若预览期间状态又有
变化，弹窗只刷新内容，不执行写入。ProxyJump key 按依赖顺序逐个展示。

终端中的 `sloosh host trust myhost` 提供同样的人类专用流程。连接测试遇到未信任或变化的
key 时会先打开该弹窗；路由上的 key 全部受信任后自动重试普通 lease 流程，并依次验证 TCP、
SSH handshake、host key、配置的认证方式与 SSH session channel，不执行 Unix 命令，
不创建持久 shell，整个连接测试限时 30 秒。
确认后的连接错误仍显示在 Hosts 页面。系统明确别名使用 SSH config 中的 hostname、port 和
route，不受旧 vault 副本遮蔽；其他 vault 主机使用保存的配置。删除 vault 主机会移除记录及
密码；已有 SSH session 仍保持连接。

Agent 可显式执行 `sloosh request --trust-new-host myhost`：完成正常租约授权后，
每个请求主机尝试一次 SSH 连接（限时 30 秒），记录目标及跳板首次出现的密钥。
已变更密钥（含算法变更）仍拒绝，不开启危险绕过，也不跳过认证或租约检查。
首次信任无法独立验证服务器身份。授权待定时不连接；批准后重新执行带参数的请求。
连接失败不撤销已授予租约或本次已记录的密钥。之后正常使用 `sloosh run`。

达到配置的空闲期，或发生系统睡眠、锁屏、切换用户、手动锁定、退出 App、绝对会话上限时，
App 会锁定 vault session。凭据、超时与审批边界以
[SECURITY.md](../SECURITY.md) 为准。

## 批准访问

未开启 Dangerous Bypass Mode 时，使用主机前先请求 lease：

```sh
sloosh request myhost
```

仅在输出 `authorized` 后继续。如果输出 pending 审批命令，由人类在另一终端执行原命令：

```sh
sloosh approve REQUEST_ID_FROM_OUTPUT
```

若完整 scope 仅使用系统 SSH Agent，`request` 无需人工批准即可激活限时 lease。其他
scope 在配置完成的 macOS DMG 安装中会先用有界、可滚动列表显示全部目标主机与
ProxyJump 依赖，再直接提供 Touch ID、审批 PIN、vault Master Password 三个按钮；
点击即进入对应安全认证，不再先列表选择再点 Continue。未知 host key 仍需人类在终端
审批流程或已解锁的桌面 Hosts 页面核对指纹；ProxyJump 路由会在授权前校验。

## 持久会话

默认会话会保留工作目录、环境变量与后台任务：

```sh
sloosh run myhost "cd /srv/app"
sloosh run myhost "export APP_ENV=production"
sloosh run myhost "npm test"
```

命令返回 `running` 时，应继续查看原执行，不要重复启动：

```sh
sloosh peek myhost
sloosh interrupt myhost
```

交互输入与并行会话：

```sh
sloosh send myhost "y" --newline
sloosh open myhost deploy
sloosh run --session deploy myhost "./deploy.sh"
sloosh peek --session deploy myhost
sloosh ls --host myhost
sloosh kill --session deploy myhost
```

## 文件传输

传输复用已授权的 SSH 连接：

```sh
sloosh put myhost ./build.tar.gz /srv/app/build.tar.gz
sloosh get myhost /var/log/app.log ./app.log
```

`put` 会截断远端目标且不保证远端原子性；中断可能留下不完整文件。`get` 默认拒绝覆盖
已有本地文件，只有明确使用 `--force` 才覆盖。传输保证见
[架构](internals/architecture.md)与[安全模型](../SECURITY.md)。

## 端口转发

```sh
sloosh forward myhost -L 8080:127.0.0.1:80
sloosh forward myhost -R 9000:127.0.0.1:3000
sloosh forward ls
sloosh forward stop FORWARD_ID
```

本地转发只绑定 loopback。远程转发会主动在 SSH 服务器创建监听，其暴露范围取决于 sshd
`GatewayPorts`；使用 `-R` 前请阅读 [SECURITY.md](../SECURITY.md)。

## Vault 与审批超时

```sh
sloosh vault timeout
sloosh vault timeout 15
```

该值由桌面 vault 与空闲 CLI/Agent lease 共用，但不会替代系统 Agent 自动策略之外的批准。
精确 lease 与 vault 规则以 [SECURITY.md](../SECURITY.md) 为准。

## 状态、日志与 daemon

排障先运行：

```sh
sloosh status
sloosh log -n 50
sloosh daemon status
```

专用 `slooshd` 通常按需自动启动，不应直接运行。生命周期控制命令见
`sloosh daemon --help`，只在排障时使用。

命令警告与错误写入 stderr，正常结果保留在 stdout。后台 daemon 诊断写入
`~/.sloosh/daemon.log`。运行期警告包含稳定 `diagnostic_code`；重复后台故障以
`suppressed=N` 聚合，不会逐条刷屏；后续成功能证明恢复时，只记录一次恢复事件。
可用 `RUST_LOG=debug` 为任一二进制启用更多细节；分享前必须检查并脱敏日志。

## 命令参考

运行 `sloosh --help` 查看命令列表，运行 `sloosh <command> --help` 查看参数。
协议与组件细节见[协议](internals/protocol.md)和[架构](internals/architecture.md)；
支持渠道见 [SUPPORT.md](../SUPPORT.md)。
