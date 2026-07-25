# 云端 MCP 式 SSH 操作调研（截至 2026-07-24）

> 非权威、时效性研究记录，不定义 sloosh 的已发布行为。

范围：只采用厂商文档、协议文档或项目原始仓库。这里的“不用在用户本地部署”特指 MCP 客户端从云端连接工具服务；并不等于目标主机无需任何网络通道、代理或凭据。

## 结论摘要

- **事实**：市面上已经出现至少两种“用户电脑不运行 MCP/SSH 进程，托管网关直接 SSH 到任意目标”的公开样本：MCP Express 与 Lightcap 托管的 MCP Nexus。前者让用户在控制台配置主机与 SSH 私钥/密码，后者在 OAuth consent 阶段绑定 SSH 目标和凭据。[MCP Express](https://www.mcp-express.com/blogs/manage-servers-through-ai-using-ssh-mcp/)；[MCP Nexus](https://github.com/farukalpay/mcp-nexus)
- **事实**：Anthropic 的 remote MCP connector 由 Anthropic 云端发起请求，服务器必须能从公网（或放行 Anthropic IP 段）访问；本地 `claude_desktop_config.json` 的 stdio MCP 是另一条路径，使用本机网络。[Anthropic Remote MCP](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)
- **事实**：MCP 只规定 AI 客户端与工具服务之间的 JSON-RPC 传输。`stdio` 由客户端启动本地子进程；Streamable HTTP 连接独立远程进程。MCP 本身不提供到 SSH 目标的路由、SSH 认证或 host-key 校验。[MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- **事实**：AWS Systems Manager Run Command、Azure VM/Arc Run Command 是“云 API → 云/客体代理 → shell”的远程执行，不是 SSH；目标机安装并运行 SSM Agent/VM Agent/Connected Machine agent，并需要出站控制面连接。[AWS Run Command](https://docs.aws.amazon.com/systems-manager/latest/userguide/run-command.html)；[Azure Linux Run Command](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/run-command)；[Azure Arc Run Command](https://learn.microsoft.com/en-us/azure/azure-arc/servers/run-command)
- **事实**：可查到的 SSH MCP 开源样本（如 `classfang/ssh-mcp-server`、`tufantunc/ssh-mcp`）默认是客户端本地启动的 stdio 进程；“云托管”不是其仓库已证明的部署形态。[classfang/ssh-mcp-server](https://github.com/classfang/ssh-mcp-server)；[tufantunc/ssh-mcp](https://github.com/tufantunc/ssh-mcp)
- **推断**：真正无本机部署的 SSH-MCP 必须把 SSH 私钥/密码、known_hosts、跳板网络和执行审计放入云端信任边界；若目标在私网，需同 VPC、VPN、专线、反向隧道、跳板或驻留 connector。宣传中的“只需 SSH”只能证明目标侧无需专用 agent，不能证明网络可达。

## 架构分类

| 类别 | 控制路径 | 目标侧依赖 | 凭据/网络事实 | 是否真正无本地部署 |
|---|---|---|---|---|
| 托管 Remote MCP → SSH gateway | 模型/客户端 → HTTPS(SSE/Streamable HTTP) → 托管 MCP → SSH/SFTP → 目标 | SSH 服务对网关可达；无需目标专用 agent | MCP Express/MCP Nexus 网关接收目标与 SSH 凭据；凭据进入第三方云信任边界 | **是（对用户电脑）**，但需云端凭据和可达路径 |
| 通用 MCP 托管平台 | 用户把开源 SSH-MCP 部署到 MCP hosting → Streamable HTTP → SSH | 同上 | 平台运行用户选择的 npm/uvx/容器；SSH 密钥需作为托管 secret 注入 | **可做到**，但不是现成 SSH 产品 |
| 本地 stdio SSH-MCP | 客户端 → 本地 MCP 子进程 → SSH | 无目标 agent，仅 SSH | `classfang` 参数含 host/user/password/privateKey；凭据在本地配置 | 否 |
| 云厂商 agent Run Command | API → SSM/VM/Connected Machine agent → shell | 必须安装/注册 agent，agent 出站到云 | AWS 支持 EC2/混合节点；Azure Run Command 可在 SSH 端口关闭时执行；Azure 文档要求出站 443 返回结果 | 是（对用户本机），但不是 SSH |
| SSH 作为 MCP transport | 本地 bridge/client → SSH → 远端 MCP providers | 远端运行 SSH/MCP 聚合服务 | Machine-to-Machine 用 SSH 承载 MCP JSON-RPC，方向与“用 MCP 管 SSH 主机”相反 | 通常仍需本地 bridge |

## 样本核验

1. **MCP Express（现成托管 SSH MCP）**：官方页面称其为 hosted MCP gateway；用户配置 IP/hostname、port、username、私钥或密码，网关再 SSH 到目标。SSH 凭据由 AWS KMS 加密；工具可用固定脚本 allowlist，也可放入 `{{query}}` 接受模型生成的任意命令。用户端只添加远程 MCP URL/OAuth，不运行本地 Node 服务。它仍处于 Early Alpha；页面声明不等同独立安全审计。[官方说明](https://www.mcp-express.com/blogs/manage-servers-through-ai-using-ssh-mcp/)
2. **MCP Nexus / Lightcap Hosted Gateway（现成托管 SSH MCP）**：开源 README 给出 `https://lightcap.ai/mcp/nexus`。ChatGPT/Claude 经 OAuth 连接；consent 页面收集 SSH host/user/port/password 或 key，access token 绑定目标，调用经 SSH connection pool 路由。官方称无需目标 agent/daemon，并有 rate limit/audit；仓库很新、采用量小，这些是项目自述而非外部验证。[源码与部署说明](https://github.com/farukalpay/mcp-nexus)
3. **MCP Nest / MCPHosting.io（通用托管层）**：平台能把 npm/uvx/自定义 stdio MCP 放到云端并暴露 Streamable HTTP/SSE。理论上可托管社区 SSH-MCP，从而免用户本机安装；平台没有替用户解决 SSH 私网可达、host key 或命令授权。[MCP Nest](https://mcpnest.dev/)；[MCPHosting.io](https://www.mcphosting.io/)
4. **Anthropic Remote MCP（客户端平台能力）**：官方帮助文档称 remote server 由开发者托管；Claude 连接从 Anthropic 云基础设施发起，服务必须可从公网访问，私网需放行其 IP。支持 SSE 与 Streamable HTTP、authless/OAuth。[文档](https://support.anthropic.com/en/articles/11175166-building-custom-integrations-via-remote-mcp-servers) / [网络要求](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)
5. **`classfang/ssh-mcp-server`（开源本地桥）**：README 定义为 SSH→MCP bridge，工具包括 execute-command、upload、download、list-servers；配置通过 MCP 客户端 `npx` 启动，支持 password/private key、SOCKS/bastion 等。[README](https://github.com/classfang/ssh-mcp-server)
6. **`tufantunc/ssh-mcp`（开源本地桥）**：README 明确称 “local Model Context Protocol server”，需 clone、`npm install`，客户端启动本地 Node 进程；因此不是云托管证据。[README](https://github.com/tufantunc/ssh-mcp)
7. **Machine-to-Machine MCP over SSH（相反方向）**：项目让本地 `uvx` client 经 SSH 访问、聚合远端 MCP providers，SSH 是 MCP 的 transport，不是让 AI 登录任意 SSH 主机做运维；可部署到云，但默认仍有本地 bridge。[官方站点](https://www.machinetomachine.ai/)；[connector](https://agenthotspot.com/connectors/oss/ssh-server)
8. **AWS Systems Manager Run Command**：官方称 managed node 可为 EC2 或混合/多云非 EC2，调用入口为 Console/CLI/SDK；节点需配置 Systems Manager。命令历史最长 30 天，可写 S3/CloudTrail；官方警告不要把密码等明文放入命令。[Run Command](https://docs.aws.amazon.com/systems-manager/latest/userguide/run-command.html)；[安全与历史](https://docs.aws.amazon.com/systems-manager/latest/userguide/running-commands.html)
9. **Azure Run Command**：Linux VM 通过 VM agent 执行 shell，可经 Portal、REST、CLI；无需开放 SSH。输出只保留最后 4,096 字节，约 20 秒最小执行时间、90 分钟最大时长、不可交互/不可取消，并要求 VM 出站 443 返回结果。[Linux Run Command](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/run-command)
10. **Azure Arc Run Command**：Connected Machine agent（1.33+）把命令发到非 Azure、AWS/GCP/OCI/本地机器；通过 Azure CLI/PowerShell/REST，仍依赖已安装 agent。[Arc 文档](https://learn.microsoft.com/en-us/azure/azure-arc/servers/run-command)

## 它实际怎样工作

MCP 与 SSH 是上下叠放的两个协议，不是 MCP “变成” SSH：

```text
AI client
  │  MCP initialize / tools/list / tools/call
  │  JSON-RPC over HTTPS + OAuth bearer
  ▼
hosted MCP gateway
  │  tenant/session → target mapping
  │  policy/approval → SSH connection pool
  │  private key/password/certificate + known_hosts
  ▼
sshd on target
  │  exec channel / PTY / SFTP / forwarding
  ▼
shell, files, services
```

1. MCP 客户端先通过 OAuth 登录托管服务，再完成 MCP initialize 和工具发现。
2. 网关按用户/会话找到目标与 SSH 凭据，做工具级授权、限流或人工批准。
3. 网关所在云网络直接连目标 TCP/22，或经 bastion/VPN/peering/tunnel 到达私网。
4. 网关执行 SSH command/PTY/SFTP，把 stdout/stderr/结构化结果转成 MCP tool result。
5. 审计系统记录“谁、何时、对哪台主机、调用哪个工具、结果状态”；秘密和命令内容是否记录需另设策略。

OAuth 只保护第一段；第二段仍需完整 SSH 安全模型。MCP session id 也不是 SSH 凭据或主机租约。

## 典型时序（抽象）

```text
用户/模型 --MCP HTTPS--> 云端 MCP 网关 --授权/策略--> SSH gateway
                                      |                 |
                                      |                 +-- known_hosts/私钥
                                      +--审计/限流       +-- SSH(22)/跳板/VPN --> 目标
```

Run Command 变体为：`用户/API → 云控制面 → 目标机 agent（轮询/出站 TLS）→ shell → agent → 云端结果`；没有 SSH 握手或 host-key 验证。

## 安全模型对比

- Remote MCP：云端服务是凭据持有者和执行权限边界；OAuth 只证明调用者身份，不自动限制 shell。公网可达要求扩大入口面；必须额外做 host-key pinning、命令策略、租约、审计和出站网络隔离。（“必须做”是推断）
- 私网可达：若目标只有 RFC1918/LAN 地址，纯公有 SaaS 无法凭 MCP/OAuth 穿透。需把网关放入同 VPC，或部署只出站的 connector/反向隧道。Cloudflare 的官方 SSH 私网方案同样要求 Tunnel/connector、路由策略、SSH CA；这说明“用户电脑免安装”与“网络内零组件”是两回事。[Cloudflare SSH infrastructure access](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/use-cases/ssh/ssh-infrastructure-access/)
- Host identity：云端网关应预置/托管 `known_hosts` 并严格校验，首次 key 必须经独立渠道核验；不能每次自动接受未知 key。[NIST known_hosts](https://csrc.nist.gov/glossary/term/known_hosts_file)
- Run Command：IAM/RBAC 授权到节点/文档；agent 身份替代 SSH 用户。AWS 明确命令会记录到 CloudTrail/S3，明文秘密可能被读取；Azure 的脚本默认非交互且有输出/时长边界。
- 本地 SSH-MCP：私钥可留在用户机，但 MCP 进程通常拥有该用户 SSH 权限；提示注入仍可驱动任意命令，除非项目的白名单/确认机制实际生效。开源 README 的“secure”属于项目声明，未等同于独立审计。

## 对 sloosh 的启发

1. sloosh 的 daemon-authority、PID+start-time lease、`SLOOSH_LEASE`、host-key fail-closed 与 bounded frames，应作为云 gateway 的不可省略语义；不要把“远程 MCP bearer/OAuth”直接当作主机租约。
2. 若增加远程 MCP 接口，建议只暴露经过策略编译的 typed tools（exec/SFTP/forward 分离），默认 loopback/私网 connector；云端不应接触 vault 明文，使用短时、主机范围、可撤销的 delegated lease。
3. 保留本地 IPC 的 `Status → Hello → ProtocolReady` 与精确协议版本；云端 transport 适配层不得改变 daemon 的授权顺序、传输上限和原子下载语义。
4. 对私网目标，文档必须明确需要 VPN/反向隧道/驻留 agent；不能以“无需本地部署”掩盖网络依赖。Run Command 可作为非 SSH 的对照实现，但其 agent、出站 443、输出/时长限制应显式建模。

## 未知与边界

- 已发现通用公网 SSH MCP 托管服务，但都很新：MCP Express 标为 Early Alpha；MCP Nexus 仓库创建时间短、采用量小。未发现这些产品的独立安全审计、SLA、host-key 处理细节或大规模生产证明。
- MCP Express 声明 KMS 加密静态凭据，但公开页面未说明解密授权边界、内存暴露、备份/删除、租户隔离和操作员访问。MCP Nexus README 声明 encrypted persisted state，但托管实例具体运维控制仍未知。
- Anthropic 文档说明连接来源和传输/认证，但未规定 SSH gateway 的 host-key、命令白名单或密钥托管方式；这些属于实现者责任。
- 云厂商 Run Command 的 agent 版本、区域、配额和计费会变化，部署前需按目标云的当前文档复核。
