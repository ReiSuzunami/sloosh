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
}

private struct Response: Encodable {
    let type: String
    let master_password: String?
    let pin: String?
    let touch_id_enrolled: Bool?
    let pin_credential_stored: Bool?
    let code: String?
    let message: String?

    static func simple(_ type: String) -> Response {
        Response(type: type, master_password: nil, pin: nil, touch_id_enrolled: nil, pin_credential_stored: nil, code: nil, message: nil)
    }

    static func unlocked(_ password: String) -> Response {
        Response(type: "unlocked", master_password: password, pin: nil, touch_id_enrolled: nil, pin_credential_stored: nil, code: nil, message: nil)
    }

    static func masterPassword(_ password: String) -> Response {
        Response(type: "master_password_entered", master_password: password, pin: nil, touch_id_enrolled: nil, pin_credential_stored: nil, code: nil, message: nil)
    }

    static func pin(_ pin: String) -> Response {
        Response(type: "pin_entered", master_password: nil, pin: pin, touch_id_enrolled: nil, pin_credential_stored: nil, code: nil, message: nil)
    }

    static func approvalStatus(touchID: Bool, pinCredential: Bool) -> Response {
        Response(type: "approval_status", master_password: nil, pin: nil, touch_id_enrolled: touchID, pin_credential_stored: pinCredential, code: nil, message: nil)
    }

    static func error(_ code: String, _ message: String) -> Response {
        Response(type: "error", master_password: nil, pin: nil, touch_id_enrolled: nil, pin_credential_stored: nil, code: code, message: message)
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

private func promptSecret(
    title: String,
    message: String,
    confirmation: Bool
) -> Response {
    activateApplication()
    let alert = NSAlert()
    alert.alertStyle = .informational
    alert.messageText = title
    alert.informativeText = message

    let first = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
    first.placeholderString = confirmation ? "Master Password" : "6-digit PIN"
    if confirmation {
        let second = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        second.placeholderString = "Confirm Master Password"
        let stack = NSStackView(views: [first, second])
        stack.orientation = .vertical
        stack.spacing = 8
        stack.frame = NSRect(x: 0, y: 0, width: 320, height: 56)
        alert.accessoryView = stack
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else {
            return .error("cancelled", "Secure input was cancelled")
        }
        guard !first.stringValue.isEmpty, first.stringValue == second.stringValue else {
            return .error("mismatch", "Master Password entries do not match")
        }
        return .masterPassword(first.stringValue)
    }

    alert.accessoryView = first
    alert.addButton(withTitle: "Continue")
    alert.addButton(withTitle: "Cancel")
    guard alert.runModal() == .alertFirstButtonReturn else {
        return .error("cancelled", "Secure input was cancelled")
    }
    guard !first.stringValue.isEmpty else {
        return .error("invalid_input", "Secure input cannot be empty")
    }
    return .pin(first.stringValue)
}

private func promptMasterPassword(purpose: String, confirmation: Bool) -> Response {
    activateApplication()
    let alert = NSAlert()
    alert.alertStyle = .informational
    alert.messageText = purpose
    alert.informativeText = confirmation
        ? "Create the Master Password used to protect your Sloosh credential vault."
        : "Enter your Master Password to authorize this security change."
    let first = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
    first.placeholderString = "Master Password"
    if confirmation {
        let second = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        second.placeholderString = "Confirm Master Password"
        let stack = NSStackView(views: [first, second])
        stack.orientation = .vertical
        stack.spacing = 8
        stack.frame = NSRect(x: 0, y: 0, width: 320, height: 56)
        alert.accessoryView = stack
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else {
            return .error("cancelled", "Master Password input was cancelled")
        }
        guard !first.stringValue.isEmpty, first.stringValue == second.stringValue else {
            return .error("mismatch", "Master Password entries do not match")
        }
    } else {
        alert.accessoryView = first
        alert.addButton(withTitle: "Continue")
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

private func promptNewPin() -> Response {
    activateApplication()
    let alert = NSAlert()
    alert.alertStyle = .informational
    alert.messageText = "Create approval PIN"
    alert.informativeText = "Choose a 6-digit PIN for local SSH approvals."
    let first = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
    first.placeholderString = "6-digit PIN"
    let second = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
    second.placeholderString = "Confirm PIN"
    let stack = NSStackView(views: [first, second])
    stack.orientation = .vertical
    stack.spacing = 8
    stack.frame = NSRect(x: 0, y: 0, width: 320, height: 56)
    alert.accessoryView = stack
    alert.addButton(withTitle: "Enable PIN")
    alert.addButton(withTitle: "Cancel")
    guard alert.runModal() == .alertFirstButtonReturn else {
        return .error("cancelled", "Approval PIN setup was cancelled")
    }
    guard first.stringValue == second.stringValue else {
        return .error("mismatch", "Approval PIN entries do not match")
    }
    return .pin(first.stringValue)
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
        return promptSecret(
            title: "Enter approval PIN",
            message: "Enter your 6-digit Sloosh approval PIN.",
            confirmation: false
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
