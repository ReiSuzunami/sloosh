# macOS/Windows 无付费开发者证书的原生生物审批可行性

## 结论

无付费开发者证书不妨碍调用本机生物认证 API；它影响的是“软件发布时的信任链”，不是 Touch ID/Windows Hello 能否弹出。LocalAuthentication 与 UserConsentVerifier 返回本机策略成功/失败（布尔或枚举），不能单独作为 daemon 可验证的授权凭据。当前 macOS 实现由固定 bundle 内 helper 校验父进程，只向该 Sloosh 进程提供 login Keychain 中的 vault 密码用于展开精确范围；用户先确认范围，再执行 Touch ID 并比对 `evaluatedPolicyDomainState`，daemon 最后激活。未来若审批跨进程、设备或网络边界，应升级为受用户在场保护的私钥签名挑战，再由 daemon 验签。

## 事实边界

1. **API 与证书无关（本机运行）**
   - Apple `LAContext.evaluatePolicy` 异步回调 `Bool`；框架明确应用拿不到指纹数据，只得到成功/失败：[LocalAuthentication](https://developer.apple.com/documentation/localauthentication/)、[evaluatePolicy](https://developer.apple.com/documentation/localauthentication/lacontext/evaluatepolicy%28_%3Alocalizedreason%3Areply%3A%29)。Apple 文档没有把 Developer ID 作为调用前提；不要把“发布签名要求”误写成“Touch ID API 需要 Developer ID”。
   - Windows `IUserConsentVerifierInterop::RequestVerificationForWindowAsync` 支持 Microsoft Passport PIN、Windows Hello、指纹读取器，并返回 `UserConsentVerificationResult`：[Microsoft API](https://learn.microsoft.com/en-us/windows/win32/api/userconsentverifierinterop/nf-userconsentverifierinterop-iuserconsentverifierinterop-requestverificationforwindowasync)。这同样是本机结果，不是可转交的密码学证明。

2. **发布信任链另算**
   - macOS Gatekeeper 对外部分发检查 Developer ID；Apple 要求 Developer ID 签名后再公证：[Developer ID](https://developer.apple.com/developer-id/)、[notarization requirements](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution?changes=_5)。Ad-hoc/local development 签名不能据此通过 Gatekeeper；不能声称 ad-hoc signing 可替代 Developer ID。
   - Windows MSIX 要求有效代码签名证书；Microsoft Store 会重新签名。Store 之外由 SmartScreen 按发布者与文件信誉评估，新的/未签名程序仍可能警告：[MSIX signing](https://learn.microsoft.com/en-us/windows/msix/package/signing-package-overview)、[SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)。
   - 因而“免费本地开发/内部分发”与“公共下载免警告”是两条不同问题；后者通常需要付费证书、商店或受信任签名服务。Windows 开源项目可评估 [SignPath Foundation](https://signpath.org/) 的免费签名服务，但仍受[项目资格与发布流程](https://signpath.org/terms.html)约束，且签名不保证新文件立即获得 SmartScreen 信誉。Apple Developer ID 只能由 Apple Developer Program 团队生成，没有等价的第三方免费证书替代。

## 无付费交付路径

- **macOS**：发布源码，让用户通过 `cargo install --git`、源码构建或包管理器在本机编译 helper；也可发布未公证预编译包，由用户在系统设置中明确放行。前者避开“下载未知可执行文件”的主要 Gatekeeper 交付问题；后者会有警告，不应通过移除 quarantine 属性来伪装可信。
- **Windows**：未签名的 unpackaged EXE 仍可使用 Win32 `UserConsentVerifierInterop` 或 WebAuthn，但 SmartScreen/Smart App Control 可能警告或阻止。符合条件的 OSS 可申请 SignPath Foundation；也可让用户从源码构建。
- **macOS PAM**：系统自带 `pam_tid.so`，社区长期用它给 `sudo` 加 Touch ID。这证明无需 Developer ID 也能走系统认证，但它需要 root 修改 PAM 策略，只返回本机认证结果，且扩大系统配置面；不适合作为 `sloosh` 默认后端。

3. **为什么不能只传成功布尔值**
   - Apple 明确 LocalAuthentication 只返回认证结果；成功布尔可被本地已被攻陷进程伪造或重放，daemon 无法独立验证“哪个密钥、哪个挑战”完成了审批。
   - Windows UserConsentVerifier 同理。UI 截图、自动点击、修改 PAM 或关闭 Gatekeeper/SmartScreen 都绕过信任边界，不形成可审计证明。

## 更强选择

- **macOS**：在 Keychain/Secure Enclave 生成不可导出签名密钥，使用 `SecAccessControl` 的 `.userPresence`（或更严格的当前生物集合约束）保护私钥；Apple 示例说明 Keychain 只在用户认证成功后放行，并可用于签名：[Keychain + Face ID/Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)、[`kSecAccessControlBiometryCurrentSet`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset?changes=_6&language=objc)、[LA access-control useKeySign](https://developer.apple.com/documentation/localauthentication/laaccesscontroloperation)。签名 `challenge || lease || request`，守护进程验签。
- **Windows**：优先 Win32 WebAuthn/Windows Hello 平台认证器，私钥由 TPM/凭据提供程序保护；协议只接受对挑战的签名，而不是 `UserConsentVerifier` 布尔。参考 [Windows WebAuthn API](https://learn.microsoft.com/en-us/windows/win32/webauthn/-webauthn-portal)、[Windows Hello](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/)。跨平台可采用 FIDO2/WebAuthn；Rust/原生集成可评估 [Yubico libfido2](https://developers.yubico.com/libfido2/)。

## sloosh 分阶段路线

1. **阶段 A（macOS 已实现）**：保留密码批准；DMG 内置 helper 将 vault 密码存入本机 login Keychain。helper 校验父进程后只向 Sloosh 提供密码；daemon 解密 vault、独立展开主机范围，原生 UI 先确认完整列表，再执行 Touch ID 并比对登记时的 biometric domain state。取消、未知 host key、未登记或 helper 缺失均退回终端审批。
2. **阶段 B（本机密码学证明）**：每台客户端生成受 user presence 保护的签名密钥；守护进程发随机 nonce，客户端完成生物审批后签名，守护进程验签并把公钥绑定设备/租约。设计重放防护、密钥轮换、撤销与无生物回退。
3. **阶段 C（发布与生态）**：需要公共下载时再接入 Apple Developer ID + notarization、Windows Store/MSIX/代码签名，或合规的 OSS 签名服务；证书预算与发布渠道独立于审批协议。

## 明确不推荐

修改 PAM、模拟系统生物 UI、抓取/注入认证窗口、关闭 Gatekeeper 或 SmartScreen，均不能提供 daemon 可独立验证的审批，且削弱平台安全边界；`sloosh` 不应采用。
