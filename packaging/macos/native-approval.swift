import AppKit
import Darwin
import Foundation
import LocalAuthentication
import Security

private let service = "io.github.reisuzunami.sloosh.native-approval"
private let account = "vault-master-password-v1"

private struct StoredCredential: Codable {
    let masterPassword: String
    let biometricDomainState: Data?
}

private enum AuthenticationResult {
    case success(Data)
    case failure(Response)
}

private enum CredentialResult {
    case success(StoredCredential)
    case failure(Response)
}

private struct Request: Decodable {
    let type: String
    let master_password: String?
    let request_id: String?
    let hosts: [String]?
    let anchor_name: String?
    let anchor_pid: UInt32?
    let allow_pin: Bool?
    let purpose: String?
    let confirm: Bool?
    let verified: Bool?
    let host_label: String?
}

private struct Response: Encodable {
    let type: String
    let master_password: String?
    let ssh_password: String?
    let pin: String?
    let touch_id_enrolled: Bool?
    let pin_credential_stored: Bool?
    let code: String?
    let message: String?

    static func simple(_ type: String) -> Response {
        Response(type: type, master_password: nil, ssh_password: nil, pin: nil, touch_id_enrolled: nil, pin_credential_stored: nil, code: nil, message: nil)
    }

    static func unlocked(_ password: String) -> Response {
        Response(type: "unlocked", master_password: password, ssh_password: nil, pin: nil, touch_id_enrolled: nil, pin_credential_stored: nil, code: nil, message: nil)
    }

    static func masterPassword(_ password: String) -> Response {
        Response(type: "master_password_entered", master_password: password, ssh_password: nil, pin: nil, touch_id_enrolled: nil, pin_credential_stored: nil, code: nil, message: nil)
    }

    static func sshPassword(_ password: String) -> Response {
        Response(type: "ssh_password_entered", master_password: nil, ssh_password: password, pin: nil, touch_id_enrolled: nil, pin_credential_stored: nil, code: nil, message: nil)
    }

    static func pin(_ pin: String) -> Response {
        Response(type: "pin_entered", master_password: nil, ssh_password: nil, pin: pin, touch_id_enrolled: nil, pin_credential_stored: nil, code: nil, message: nil)
    }

    static func approvalStatus(touchID: Bool, pinCredential: Bool) -> Response {
        Response(type: "approval_status", master_password: nil, ssh_password: nil, pin: nil, touch_id_enrolled: touchID, pin_credential_stored: pinCredential, code: nil, message: nil)
    }

    static func error(_ code: String, _ message: String) -> Response {
        Response(type: "error", master_password: nil, ssh_password: nil, pin: nil, touch_id_enrolled: nil, pin_credential_stored: nil, code: code, message: message)
    }
}

private func send(_ response: Response) {
    guard let data = try? JSONEncoder().encode(response) else {
        exit(1)
    }
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([0x0a]))
}

private func receive() -> Request? {
    guard let line = readLine(), let data = line.data(using: .utf8) else {
        return nil
    }
    return try? JSONDecoder().decode(Request.self, from: data)
}

private func keychainBaseQuery() -> [CFString: Any] {
    [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecAttrAccount: account,
    ]
}

private func isTrustedParent() -> Bool {
    var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    let length = proc_pidpath(getppid(), &buffer, UInt32(buffer.count))
    guard length > 0 else {
        return false
    }
    let parentPath = String(cString: buffer)
    let contents = Bundle.main.bundleURL
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let actualPath = URL(fileURLWithPath: parentPath)
        .standardizedFileURL
        .resolvingSymlinksInPath()
        .path
    let trustedPaths = [
        contents.appendingPathComponent("MacOS/Sloosh"),
        contents.appendingPathComponent("MacOS/sloosh"),
        contents.appendingPathComponent("Helpers/sloosh"),
    ].map { $0.standardizedFileURL.resolvingSymlinksInPath().path }
    return trustedPaths.contains(actualPath)
}

private func authenticate(reason: String) -> AuthenticationResult {
    let context = LAContext()
    context.localizedFallbackTitle = ""
    var policyError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyError),
          context.biometryType == .touchID else {
        return .failure(.error("unavailable", policyError?.localizedDescription ?? "Touch ID is unavailable"))
    }

    let semaphore = DispatchSemaphore(value: 0)
    var succeeded = false
    var evaluationError: Error?
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
        succeeded = success
        evaluationError = error
        semaphore.signal()
    }
    semaphore.wait()

    guard succeeded, let domainState = context.evaluatedPolicyDomainState else {
        let code = (evaluationError as? LAError)?.code
        if code == .userCancel || code == .systemCancel || code == .appCancel || code == .userFallback {
            return .failure(.error("cancelled", "Touch ID approval was cancelled"))
        }
        return .failure(.error("unavailable", evaluationError?.localizedDescription ?? "Touch ID authentication failed"))
    }
    return .success(domainState)
}

private func saveCredential(password: String, domainState: Data?) -> Response {
    let stored = StoredCredential(
        masterPassword: password,
        biometricDomainState: domainState
    )
    guard let encoded = try? JSONEncoder().encode(stored) else {
        return .error("keychain", "Could not encode native approval credential")
    }

    let base = keychainBaseQuery()
    let deleteStatus = SecItemDelete(base as CFDictionary)
    guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
        return .error("keychain", SecCopyErrorMessageString(deleteStatus, nil) as String? ?? "Keychain error \(deleteStatus)")
    }
    var item = base
    item[kSecValueData] = encoded
    let status = SecItemAdd(item as CFDictionary, nil)
    guard status == errSecSuccess else {
        return .error("keychain", SecCopyErrorMessageString(status, nil) as String? ?? "Keychain error \(status)")
    }
    return .simple("credential_stored")
}

private func enroll(password: String) -> Response {
    let domainState: Data
    switch authenticate(reason: "Enable Touch ID approval for Sloosh") {
    case .success(let state):
        domainState = state
    case .failure(let response):
        return response
    }

    let response = saveCredential(password: password, domainState: domainState)
    return response.type == "credential_stored" ? .simple("enrolled") : response
}

private func loadCredential() -> CredentialResult {
    var query = keychainBaseQuery()
    query[kSecReturnData] = true
    query[kSecMatchLimit] = kSecMatchLimitOne

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
        return .failure(.error("not_enrolled", "Touch ID approval is not enrolled"))
    }
    guard status == errSecSuccess,
          let data = result as? Data,
          let stored = try? JSONDecoder().decode(StoredCredential.self, from: data) else {
        return .failure(.error("keychain", SecCopyErrorMessageString(status, nil) as String? ?? "Keychain error \(status)"))
    }
    return .success(stored)
}

private func activateApplication() {
    NSApplication.shared.setActivationPolicy(.accessory)
    NSApplication.shared.activate(ignoringOtherApps: true)
}

private final class PINCodeInputView: NSView, NSTextFieldDelegate {
    private static let digitCount = 6
    private let fields: [NSSecureTextField]
    private let autofocus: Bool
    private var updating = false

    weak var nextInput: PINCodeInputView?
    var onChange: (() -> Void)?

    var pin: String {
        fields.map(\.stringValue).joined()
    }

    var isComplete: Bool {
        fields.allSatisfy { $0.stringValue.count == 1 }
    }

    override var intrinsicContentSize: NSSize {
        NSSize(width: 320, height: 68)
    }

    init(label: String, autofocus: Bool = false) {
        self.autofocus = autofocus
        fields = (0..<Self.digitCount).map { index in
            let field = NSSecureTextField(frame: .zero)
            field.tag = index
            field.alignment = .center
            field.font = .monospacedDigitSystemFont(ofSize: 20, weight: .medium)
            field.focusRingType = .exterior
            field.maximumNumberOfLines = 1
            field.setAccessibilityLabel("\(label) digit \(index + 1) of \(Self.digitCount)")
            return field
        }
        super.init(frame: NSRect(x: 0, y: 0, width: 320, height: 68))

        let labelField = NSTextField(labelWithString: label)
        labelField.font = .systemFont(ofSize: 12, weight: .medium)
        labelField.textColor = .secondaryLabelColor

        let row = NSStackView(views: fields)
        row.orientation = .horizontal
        row.alignment = .centerY
        row.distribution = .fillEqually
        row.spacing = 8

        let stack = NSStackView(views: [labelField, row])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 6
        stack.frame = bounds
        stack.autoresizingMask = [.width, .height]
        addSubview(stack)

        for field in fields {
            field.delegate = self
            field.widthAnchor.constraint(equalToConstant: 46).isActive = true
            field.heightAnchor.constraint(equalToConstant: 38).isActive = true
        }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        guard autofocus, window != nil else {
            return
        }
        DispatchQueue.main.async { [weak self] in
            self?.focusField(at: 0)
        }
    }

    func focusFirstField() {
        focusField(at: 0)
    }

    func controlTextDidChange(_ notification: Notification) {
        guard !updating,
              let field = notification.object as? NSSecureTextField,
              fields.indices.contains(field.tag) else {
            return
        }

        let index = field.tag
        let digits = Self.asciiDigits(in: field.stringValue)
        updating = true
        if digits.count > 1 {
            for target in index..<fields.count {
                fields[target].stringValue = ""
            }
            for (offset, digit) in digits.prefix(fields.count - index).enumerated() {
                fields[index + offset].stringValue = String(digit)
            }
        } else {
            field.stringValue = digits.first.map(String.init) ?? ""
        }
        updating = false
        onChange?()

        guard !digits.isEmpty else {
            return
        }
        let nextIndex = min(index + digits.count, fields.count)
        if nextIndex < fields.count {
            focusField(at: nextIndex)
        } else if let nextInput {
            nextInput.focusFirstField()
        }
    }

    func control(
        _ control: NSControl,
        textView: NSTextView,
        doCommandBy commandSelector: Selector
    ) -> Bool {
        guard let field = control as? NSSecureTextField,
              fields.indices.contains(field.tag) else {
            return false
        }
        let index = field.tag

        if commandSelector == #selector(NSResponder.deleteBackward(_:)) {
            if field.stringValue.isEmpty, index > 0 {
                fields[index - 1].stringValue = ""
                focusField(at: index - 1)
            } else {
                field.stringValue = ""
                focusField(at: index)
            }
            onChange?()
            return true
        }
        if commandSelector == #selector(NSResponder.insertTab(_:)) {
            if index + 1 < fields.count {
                focusField(at: index + 1)
            } else if let nextInput {
                nextInput.focusFirstField()
            }
            return true
        }
        if commandSelector == #selector(NSResponder.insertBacktab(_:)), index > 0 {
            focusField(at: index - 1)
            return true
        }
        return false
    }

    private func focusField(at index: Int) {
        guard fields.indices.contains(index) else {
            return
        }
        window?.makeFirstResponder(fields[index])
        fields[index].selectText(nil)
    }

    private static func asciiDigits(in value: String) -> [Character] {
        value.unicodeScalars.compactMap { scalar in
            guard (48...57).contains(scalar.value) else {
                return nil
            }
            return Character(String(scalar))
        }
    }
}

private func promptPin(title: String, message: String) -> Response {
    activateApplication()
    let alert = NSAlert()
    alert.alertStyle = .informational
    alert.messageText = title
    alert.informativeText = message

    let input = PINCodeInputView(label: "PIN", autofocus: true)
    alert.accessoryView = input
    let continueButton = alert.addButton(withTitle: "Continue")
    continueButton.isEnabled = false
    alert.addButton(withTitle: "Cancel")
    input.onChange = { [weak input, weak continueButton] in
        continueButton?.isEnabled = input?.isComplete == true
    }
    guard alert.runModal() == .alertFirstButtonReturn else {
        return .error("cancelled", "Approval PIN input was cancelled")
    }
    guard input.isComplete else {
        return .error("invalid_input", "Approval PIN must contain exactly 6 digits")
    }
    return .pin(input.pin)
}

private func labeledSecureField(
    label: String,
    placeholder: String
) -> (view: NSStackView, field: NSSecureTextField) {
    let labelField = NSTextField(labelWithString: label)
    labelField.font = .systemFont(ofSize: 12, weight: .semibold)
    labelField.textColor = .labelColor

    let field = NSSecureTextField(frame: .zero)
    field.placeholderString = placeholder
    field.setAccessibilityLabel(label)
    field.widthAnchor.constraint(equalToConstant: 320).isActive = true
    field.heightAnchor.constraint(equalToConstant: 28).isActive = true

    let stack = NSStackView(views: [labelField, field])
    stack.orientation = .vertical
    stack.alignment = .leading
    stack.spacing = 6
    stack.frame = NSRect(x: 0, y: 0, width: 320, height: 52)
    return (stack, field)
}

private func promptMasterPassword(purpose: String, confirmation: Bool) -> Response {
    activateApplication()
    let alert = NSAlert()
    alert.alertStyle = .informational
    alert.icon = NSImage(
        systemSymbolName: "lock.shield.fill",
        accessibilityDescription: "Master Password"
    )
    alert.messageText = confirmation ? "Create Master Password" : "Master Password required"
    alert.informativeText = confirmation
        ? "Protect your Sloosh credential vault. This is separate from the 6-digit approval PIN."
        : "Authorize \"\(purpose)\" with your vault Master Password, not your approval PIN."
    let firstSection = labeledSecureField(
        label: confirmation ? "New Master Password" : "Master Password",
        placeholder: "Enter vault password"
    )
    let first = firstSection.field
    if confirmation {
        let secondSection = labeledSecureField(
            label: "Confirm Master Password",
            placeholder: "Enter vault password again"
        )
        let second = secondSection.field
        let stack = NSStackView(views: [firstSection.view, secondSection.view])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 12
        stack.frame = NSRect(x: 0, y: 0, width: 320, height: 116)
        firstSection.view.widthAnchor.constraint(equalToConstant: 320).isActive = true
        firstSection.view.heightAnchor.constraint(equalToConstant: 52).isActive = true
        secondSection.view.widthAnchor.constraint(equalToConstant: 320).isActive = true
        secondSection.view.heightAnchor.constraint(equalToConstant: 52).isActive = true
        alert.accessoryView = stack
        DispatchQueue.main.async {
            alert.window.makeFirstResponder(first)
        }
        alert.addButton(withTitle: "Create Vault")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else {
            return .error("cancelled", "Master Password input was cancelled")
        }
        guard !first.stringValue.isEmpty, first.stringValue == second.stringValue else {
            return .error("mismatch", "Master Password entries do not match")
        }
    } else {
        alert.accessoryView = firstSection.view
        DispatchQueue.main.async {
            alert.window.makeFirstResponder(first)
        }
        alert.addButton(withTitle: "Authorize")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else {
            return .error("cancelled", "Master Password input was cancelled")
        }
        guard !first.stringValue.isEmpty else {
            return .error("invalid_input", "Master Password cannot be empty")
        }
    }
    return .masterPassword(first.stringValue)
}

private func promptSshPassword(hostLabel: String) -> Response {
    activateApplication()
    let alert = NSAlert()
    alert.alertStyle = .informational
    alert.icon = NSImage(
        systemSymbolName: "key.fill",
        accessibilityDescription: "SSH Password"
    )
    alert.messageText = "SSH Password"
    alert.informativeText = "Enter the SSH password stored for \"\(hostLabel)\". It stays outside the Sloosh control panel."
    let section = labeledSecureField(
        label: "SSH Password",
        placeholder: "Enter remote account password"
    )
    alert.accessoryView = section.view
    DispatchQueue.main.async {
        alert.window.makeFirstResponder(section.field)
    }
    alert.addButton(withTitle: "Continue")
    alert.addButton(withTitle: "Cancel")
    guard alert.runModal() == .alertFirstButtonReturn else {
        return .error("cancelled", "SSH Password input was cancelled")
    }
    guard !section.field.stringValue.isEmpty else {
        return .error("invalid_input", "SSH Password cannot be empty")
    }
    return .sshPassword(section.field.stringValue)
}

private func promptNewPin() -> Response {
    activateApplication()
    let alert = NSAlert()
    alert.alertStyle = .informational
    alert.messageText = "Create approval PIN"
    alert.informativeText = "Choose a 6-digit PIN for local SSH approvals."
    let first = PINCodeInputView(label: "New PIN", autofocus: true)
    let second = PINCodeInputView(label: "Confirm PIN")
    first.nextInput = second
    let stack = NSStackView(views: [first, second])
    stack.orientation = .vertical
    stack.alignment = .leading
    stack.distribution = .fill
    stack.spacing = 12
    stack.frame = NSRect(x: 0, y: 0, width: 320, height: 148)
    first.widthAnchor.constraint(equalToConstant: 320).isActive = true
    first.heightAnchor.constraint(equalToConstant: 68).isActive = true
    second.widthAnchor.constraint(equalToConstant: 320).isActive = true
    second.heightAnchor.constraint(equalToConstant: 68).isActive = true
    alert.accessoryView = stack
    let enableButton = alert.addButton(withTitle: "Enable PIN")
    enableButton.isEnabled = false
    alert.addButton(withTitle: "Cancel")
    let updateButton = { [weak first, weak second, weak enableButton] in
        guard let first, let second else {
            enableButton?.isEnabled = false
            return
        }
        enableButton?.isEnabled = first.isComplete
            && second.isComplete
            && first.pin == second.pin
    }
    first.onChange = updateButton
    second.onChange = updateButton
    guard alert.runModal() == .alertFirstButtonReturn else {
        return .error("cancelled", "Approval PIN setup was cancelled")
    }
    guard first.isComplete, second.isComplete else {
        return .error("invalid_input", "Approval PIN must contain exactly 6 digits")
    }
    guard first.pin == second.pin else {
        return .error("mismatch", "Approval PIN entries do not match")
    }
    return .pin(first.pin)
}

private func confirm(
    hosts: [String],
    enrolledDomainState: Data?,
    allowPin: Bool
) -> Response {
    activateApplication()

    let alert = NSAlert()
    alert.alertStyle = .informational
    alert.messageText = "Approve SSH access?"
    let escapedHosts = hosts.map { "- \($0.debugDescription)" }.joined(separator: "\n")
    alert.informativeText = "Sloosh will grant this request access to:\n\n\(escapedHosts)"
    if enrolledDomainState != nil {
        alert.addButton(withTitle: "Use Touch ID")
    }
    if allowPin {
        alert.addButton(withTitle: "Use PIN")
    }
    guard enrolledDomainState != nil || allowPin else {
        return .error("not_enrolled", "No local approval method is configured")
    }
    alert.addButton(withTitle: "Cancel")
    let answer = alert.runModal()
    let selectedTouchID = enrolledDomainState != nil && answer == .alertFirstButtonReturn
    let selectedPIN = allowPin && (
        (enrolledDomainState == nil && answer == .alertFirstButtonReturn)
            || (enrolledDomainState != nil && answer == .alertSecondButtonReturn)
    )
    guard selectedTouchID || selectedPIN else {
        return .error("cancelled", "Native approval was cancelled")
    }
    if selectedPIN {
        return promptPin(
            title: "Enter approval PIN",
            message: "Enter your 6-digit Sloosh approval PIN."
        )
    }

    let currentDomainState: Data
    switch authenticate(reason: "Approve Sloosh access to \(hosts.joined(separator: ", "))") {
    case .success(let state):
        currentDomainState = state
    case .failure(let response):
        return response
    }
    guard enrolledDomainState == currentDomainState else {
        return .error("not_enrolled", "Touch ID enrollment changed; run `sloosh init` again")
    }
    return .simple("approved")
}

private func storePinCredential(password: String) -> Response {
    let domainState: Data?
    switch loadCredential() {
    case .success(let credential):
        domainState = credential.biometricDomainState
    case .failure(let response):
        guard response.code == "not_enrolled" else {
            return response
        }
        domainState = nil
    }
    let response = saveCredential(password: password, domainState: domainState)
    return response.type == "credential_stored" ? .simple("pin_credential_stored") : response
}

private func removePinCredential() -> Response {
    switch loadCredential() {
    case .success(let credential):
        if credential.biometricDomainState != nil {
            return .simple("pin_credential_removed")
        }
        let status = SecItemDelete(keychainBaseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            return .error("keychain", SecCopyErrorMessageString(status, nil) as String? ?? "Keychain error \(status)")
        }
        return .simple("pin_credential_removed")
    case .failure(let response):
        return response.code == "not_enrolled" ? .simple("pin_credential_removed") : response
    }
}

guard isTrustedParent() else {
    send(.error("untrusted_parent", "Native approval helper must be launched by Sloosh"))
    exit(1)
}

guard let first = receive() else {
    send(.error("invalid_request", "Missing or invalid helper request"))
    exit(1)
}

switch first.type {
case "status":
    switch loadCredential() {
    case .success(let credential):
        send(.approvalStatus(
            touchID: credential.biometricDomainState != nil,
            pinCredential: true
        ))
        exit(0)
    case .failure(let response):
        if response.code == "not_enrolled" {
            send(.approvalStatus(touchID: false, pinCredential: false))
            exit(0)
        }
        send(response)
        exit(1)
    }

case "unlock_with_touch_id":
    let stored: StoredCredential
    switch loadCredential() {
    case .success(let credential):
        stored = credential
    case .failure(let response):
        send(response)
        exit(1)
    }
    guard let enrolledDomainState = stored.biometricDomainState else {
        send(.error("not_enrolled", "Touch ID approval is not enrolled"))
        exit(1)
    }
    let currentDomainState: Data
    switch authenticate(reason: "Unlock Sloosh") {
    case .success(let state):
        currentDomainState = state
    case .failure(let response):
        send(response)
        exit(1)
    }
    guard enrolledDomainState == currentDomainState else {
        send(.error("not_enrolled", "Touch ID enrollment changed; re-enroll it in Sloosh"))
        exit(1)
    }
    send(.unlocked(stored.masterPassword))
    exit(0)

case "begin_pin_unlock":
    let stored: StoredCredential
    switch loadCredential() {
    case .success(let credential):
        stored = credential
    case .failure(let response):
        send(response)
        exit(1)
    }
    let response = promptPin(
        title: "Unlock Sloosh",
        message: "Enter your 6-digit Sloosh PIN."
    )
    send(response)
    guard response.type == "pin_entered" else {
        exit(1)
    }
    guard let second = receive(),
          second.type == "complete_pin_unlock",
          let verified = second.verified else {
        send(.error("invalid_request", "Missing PIN verification result"))
        exit(1)
    }
    guard verified else {
        send(.simple("pin_rejected"))
        exit(0)
    }
    send(.unlocked(stored.masterPassword))
    exit(0)

case "enroll":
    guard let password = first.master_password else {
        send(.error("invalid_request", "Enrollment password is missing"))
        exit(1)
    }
    let response = enroll(password: password)
    send(response)
    exit(response.type == "enrolled" ? 0 : 1)

case "prompt_master_password":
    let response = promptMasterPassword(
        purpose: first.purpose ?? "Authorize Sloosh",
        confirmation: first.confirm ?? false
    )
    send(response)
    exit(response.type == "master_password_entered" ? 0 : 1)

case "prompt_ssh_password":
    let response = promptSshPassword(hostLabel: first.host_label ?? "SSH host")
    send(response)
    exit(response.type == "ssh_password_entered" ? 0 : 1)

case "prompt_pin":
    let response = promptNewPin()
    send(response)
    exit(response.type == "pin_entered" ? 0 : 1)

case "store_pin_credential":
    guard let password = first.master_password else {
        send(.error("invalid_request", "Master Password is missing"))
        exit(1)
    }
    let response = storePinCredential(password: password)
    send(response)
    exit(response.type == "pin_credential_stored" ? 0 : 1)

case "remove_pin_credential":
    let response = removePinCredential()
    send(response)
    exit(response.type == "pin_credential_removed" ? 0 : 1)

case "begin":
    let stored: StoredCredential
    switch loadCredential() {
    case .success(let credential):
        stored = credential
    case .failure(let response):
        send(response)
        exit(1)
    }
    send(.unlocked(stored.masterPassword))
    guard let second = receive(), second.type == "confirm", let hosts = second.hosts else {
        send(.error("invalid_request", "Missing host confirmation request"))
        exit(1)
    }
    let confirmation = confirm(
        hosts: hosts,
        enrolledDomainState: stored.biometricDomainState,
        allowPin: second.allow_pin ?? false
    )
    send(confirmation)
    exit(confirmation.type == "approved" || confirmation.type == "pin_entered" ? 0 : 1)

default:
    send(.error("invalid_request", "Unsupported helper request"))
    exit(1)
}
