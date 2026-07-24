#!/usr/bin/env swift

import AppKit
import Darwin
import Foundation
import Security

private let fileManager = FileManager.default
private let bundleIdentifier = "io.github.reisuzunami.sloosh"

private enum InstallerFailure: LocalizedError {
    case message(String)

    var errorDescription: String? {
        switch self {
        case let .message(message): message
        }
    }
}

private enum NodeKind {
    case missing
    case directory
    case symbolicLink
    case socket
    case other
}

private struct InstallResult {
    let targetApp: URL
    let cliMessage: String
}

private func nodeKind(at url: URL) throws -> NodeKind {
    var info = stat()
    if lstat(url.path, &info) == 0 {
        switch info.st_mode & S_IFMT {
        case S_IFDIR: return .directory
        case S_IFLNK: return .symbolicLink
        case S_IFSOCK: return .socket
        default: return .other
        }
    }
    if errno == ENOENT {
        return .missing
    }
    throw InstallerFailure.message("Could not inspect \(url.path): \(String(cString: strerror(errno)))")
}

private func requireDirectory(_ url: URL, create: Bool) throws {
    switch try nodeKind(at: url) {
    case .directory:
        return
    case .missing where create:
        do {
            try fileManager.createDirectory(at: url, withIntermediateDirectories: false)
        } catch {
            throw InstallerFailure.message("Could not create \(url.path): \(error.localizedDescription)")
        }
    case .symbolicLink:
        throw InstallerFailure.message("Refusing to use symbolic-link directory \(url.path).")
    case .missing:
        throw InstallerFailure.message("Directory does not exist: \(url.path)")
    case .socket, .other:
        throw InstallerFailure.message("Expected a directory at \(url.path).")
    }
}

private func isRecognizedSlooshBundle(at url: URL) throws -> Bool {
    guard try nodeKind(at: url) == .directory,
          let bundle = Bundle(url: url),
          bundle.bundleIdentifier == bundleIdentifier,
          let executableName = bundle.object(forInfoDictionaryKey: "CFBundleExecutable") as? String
    else {
        return false
    }
    let executable = url.appendingPathComponent("Contents/MacOS/\(executableName)")
    let helper = url.appendingPathComponent("Contents/Helpers/sloosh")
    guard fileManager.isExecutableFile(atPath: executable.path) else {
        return false
    }
    if executableName == "Sloosh" {
        return try nodeKind(at: helper) == .other
            && fileManager.isExecutableFile(atPath: helper.path)
    }
    guard executableName == "sloosh",
          try nodeKind(at: helper) == .symbolicLink
    else {
        return false
    }
    return try fileManager.destinationOfSymbolicLink(atPath: helper.path) == "../MacOS/sloosh"
}

private func validateCodeSignature(at url: URL) throws {
    var code: SecStaticCode?
    let createStatus = SecStaticCodeCreateWithPath(url as CFURL, [], &code)
    guard createStatus == errSecSuccess, let code else {
        throw InstallerFailure.message("Could not inspect the Sloosh payload signature (OSStatus \(createStatus)).")
    }
    let flags = SecCSFlags(rawValue: UInt32(kSecCSStrictValidate | kSecCSCheckAllArchitectures))
    let validationStatus = SecStaticCodeCheckValidity(code, flags, nil)
    guard validationStatus == errSecSuccess else {
        throw InstallerFailure.message("Sloosh application payload has an invalid signature (OSStatus \(validationStatus)).")
    }
}

private func validatedSlooshBundle(at url: URL) throws {
    guard try isRecognizedSlooshBundle(at: url) else {
        throw InstallerFailure.message("Sloosh application payload is missing or malformed.")
    }
    try validateCodeSignature(at: url)
}

private func canonicalPath(_ url: URL) -> String {
    url.standardizedFileURL.resolvingSymlinksInPath().path
}

private func runningTargetApplications(at target: URL) -> [NSRunningApplication] {
    let targetPath = canonicalPath(target)
    let targetExecutablePath = canonicalPath(
        target.appendingPathComponent("Contents/MacOS/Sloosh")
    )
    return NSWorkspace.shared.runningApplications.filter { application in
        guard !application.isTerminated else {
            return false
        }
        if let bundleURL = application.bundleURL,
           canonicalPath(bundleURL) == targetPath {
            return true
        }
        return application.executableURL.map(canonicalPath) == targetExecutablePath
    }
}

private func waitForApplicationsToExit(
    at target: URL,
    timeout: TimeInterval
) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if runningTargetApplications(at: target).isEmpty {
            return true
        }
        // NSWorkspace publishes termination changes through AppKit's run loop.
        // A command-line installer does not otherwise drive that loop while it
        // waits, leaving NSRunningApplication state stale after termination.
        RunLoop.current.run(
            mode: .default,
            before: Date(timeIntervalSinceNow: 0.05)
        )
    }
    return runningTargetApplications(at: target).isEmpty
}

private func stopRunningApplication(at target: URL) throws {
    let applications = runningTargetApplications(at: target)
    guard !applications.isEmpty else {
        return
    }

    for application in applications {
        _ = application.terminate()
    }
    if waitForApplicationsToExit(at: target, timeout: 5) {
        return
    }

    for application in runningTargetApplications(at: target) {
        _ = application.forceTerminate()
    }
    guard waitForApplicationsToExit(at: target, timeout: 5) else {
        throw InstallerFailure.message(
            "Sloosh is still running and could not be force quit. Quit it manually, then retry the update."
        )
    }
}

private func stopExistingDaemon(home: URL) throws {
    let socket = home.appendingPathComponent(".sloosh/sloosh.sock")
    switch try nodeKind(at: socket) {
    case .missing:
        return
    case .socket:
        break
    default:
        throw InstallerFailure.message(
            "Refusing unexpected daemon socket item at \(socket.path). Run `sloosh daemon stop` and retry."
        )
    }

    let input = Pipe()
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/nc")
    process.arguments = ["-U", socket.path]
    process.standardInput = input
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice

    do {
        try process.run()
        input.fileHandleForWriting.write(Data("{\"type\":\"Shutdown\"}\n".utf8))
        try input.fileHandleForWriting.close()
    } catch {
        throw InstallerFailure.message(
            "Could not request daemon shutdown. Run `sloosh daemon stop` and retry."
        )
    }

    let deadline = Date().addingTimeInterval(5)
    while process.isRunning && Date() < deadline {
        usleep(50_000)
    }
    if process.isRunning {
        process.terminate()
        process.waitUntilExit()
        throw InstallerFailure.message(
            "Timed out stopping the Sloosh daemon. Run `sloosh daemon stop` and retry."
        )
    }
    guard process.terminationStatus == 0 else {
        throw InstallerFailure.message(
            "The Sloosh daemon did not stop cleanly. Run `sloosh daemon stop` and retry."
        )
    }

    let shutdownDeadline = Date().addingTimeInterval(5)
    while Date() < shutdownDeadline {
        switch try nodeKind(at: socket) {
        case .missing:
            return
        case .socket:
            usleep(50_000)
        default:
            throw InstallerFailure.message(
                "The daemon socket changed unexpectedly while stopping. Check \(socket.path) and retry."
            )
        }
    }
    throw InstallerFailure.message(
        "Timed out waiting for the Sloosh daemon to exit. Run `sloosh daemon stop` and retry."
    )
}

private func replaceApplication(
    source: URL,
    target: URL,
    home: URL,
    stopApplication: Bool,
    stopDaemon: Bool
) throws {
    try validatedSlooshBundle(at: source)
    let targetKind = try nodeKind(at: target)
    if targetKind == .symbolicLink {
        throw InstallerFailure.message("Refusing to replace symbolic link \(target.path).")
    }
    if targetKind != .missing && targetKind != .directory {
        throw InstallerFailure.message("Refusing to replace non-application item \(target.path).")
    }
    if targetKind == .directory {
        guard try isRecognizedSlooshBundle(at: target) else {
            throw InstallerFailure.message("Refusing to replace unrecognized application directory \(target.path).")
        }
    }
    if stopApplication && targetKind == .directory {
        try stopRunningApplication(at: target)
    }
    if stopDaemon && targetKind == .directory {
        try stopExistingDaemon(home: home)
    }

    let parent = target.deletingLastPathComponent()
    let nonce = UUID().uuidString
    let staged = parent.appendingPathComponent(".Sloosh.installing-\(nonce).app")
    let backup = parent.appendingPathComponent(".Sloosh.backup-\(nonce).app")

    do {
        try fileManager.copyItem(at: source, to: staged)
        try validatedSlooshBundle(at: staged)
    } catch {
        try? fileManager.removeItem(at: staged)
        throw InstallerFailure.message("Could not stage Sloosh in \(parent.path): \(error.localizedDescription)")
    }

    // Close any instance launched while the replacement was being staged.
    // The user's confirmation covers the whole update transaction, but the
    // old bundle must never be moved while one of its processes is still live.
    if stopApplication && targetKind == .directory {
        try stopRunningApplication(at: target)
    }

    if targetKind == .missing {
        do {
            try fileManager.moveItem(at: staged, to: target)
            return
        } catch {
            try? fileManager.removeItem(at: staged)
            throw InstallerFailure.message("Could not install Sloosh in \(parent.path): \(error.localizedDescription)")
        }
    }

    do {
        try fileManager.moveItem(at: target, to: backup)
        do {
            try fileManager.moveItem(at: staged, to: target)
        } catch let installError {
            do {
                try fileManager.moveItem(at: backup, to: target)
            } catch let rollbackError {
                throw InstallerFailure.message(
                    "Install failed and the previous app could not be restored. It remains at \(backup.path). Install error: \(installError.localizedDescription). Restore error: \(rollbackError.localizedDescription)"
                )
            }
            throw installError
        }
        try? fileManager.removeItem(at: backup)
    } catch {
        try? fileManager.removeItem(at: staged)
        throw InstallerFailure.message("Could not replace \(target.path): \(error.localizedDescription)")
    }
}

private func installCLILink(targetApp: URL, home: URL) -> String {
    let local = home.appendingPathComponent(".local", isDirectory: true)
    let bin = local.appendingPathComponent("bin", isDirectory: true)
    let link = bin.appendingPathComponent("sloosh")
    let helper = targetApp.appendingPathComponent("Contents/Helpers/sloosh")

    do {
        try requireDirectory(home, create: false)
        try requireDirectory(local, create: true)
        try requireDirectory(bin, create: true)

        switch try nodeKind(at: link) {
        case .missing:
            try fileManager.createSymbolicLink(at: link, withDestinationURL: helper)
            return "CLI installed at ~/.local/bin/sloosh."
        case .symbolicLink:
            let destination = try fileManager.destinationOfSymbolicLink(atPath: link.path)
            if destination == helper.path {
                return "CLI link at ~/.local/bin/sloosh is current."
            }
            return "Existing CLI link at ~/.local/bin/sloosh was left unchanged."
        case .directory, .socket, .other:
            return "Existing item at ~/.local/bin/sloosh was left unchanged."
        }
    } catch {
        return "Sloosh was installed, but its CLI link was not changed: \(error.localizedDescription)"
    }
}

private func install(
    sourceApp: URL,
    applicationsDirectory: URL,
    home: URL,
    stopApplication: Bool,
    stopDaemon: Bool
) throws -> InstallResult {
    try requireDirectory(applicationsDirectory, create: true)
    let target = applicationsDirectory.appendingPathComponent("Sloosh.app", isDirectory: true)
    try replaceApplication(
        source: sourceApp,
        target: target,
        home: home,
        stopApplication: stopApplication,
        stopDaemon: stopDaemon
    )
    return InstallResult(targetApp: target, cliMessage: installCLILink(targetApp: target, home: home))
}

private func volumeRoot(containing url: URL) -> URL? {
    var candidate = url.standardizedFileURL
    while candidate.path != "/" {
        if candidate.deletingLastPathComponent().path == "/Volumes" {
            return candidate
        }
        candidate.deleteLastPathComponent()
    }
    return nil
}

private func runProcess(_ executable: URL, arguments: [String]) throws -> (Int32, Data) {
    let process = Process()
    let output = Pipe()
    process.executableURL = executable
    process.arguments = arguments
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    try process.run()
    let data = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (process.terminationStatus, data)
}

private func diskImageURL(for mount: URL) -> URL? {
    guard let result = try? runProcess(
        URL(fileURLWithPath: "/usr/bin/hdiutil"),
        arguments: ["info", "-plist"]
    ), result.0 == 0,
    let root = try? PropertyListSerialization.propertyList(from: result.1, format: nil),
    let plist = root as? [String: Any],
    let images = plist["images"] as? [[String: Any]]
    else {
        return nil
    }

    let expectedMount = mount.standardizedFileURL.path
    for image in images {
        guard let entities = image["system-entities"] as? [[String: Any]],
              entities.contains(where: {
                  guard let path = $0["mount-point"] as? String else { return false }
                  return URL(fileURLWithPath: path).standardizedFileURL.path == expectedMount
              }),
              let path = image["image-path"] as? String
        else {
            continue
        }
        let imageURL = URL(fileURLWithPath: path).standardizedFileURL
        if imageURL.pathExtension.lowercased() == "dmg" {
            return imageURL
        }
    }
    return nil
}

private func showAlert(
    title: String,
    message: String,
    buttons: [String],
    style: NSAlert.Style = .informational
) -> NSApplication.ModalResponse {
    let alert = NSAlert()
    alert.alertStyle = style
    alert.messageText = title
    alert.informativeText = message
    for button in buttons {
        alert.addButton(withTitle: button)
    }
    NSApplication.shared.activate(ignoringOtherApps: true)
    return alert.runModal()
}

private func showCleanupError(_ message: String) {
    _ = showAlert(
        title: "Sloosh Installed",
        message: message,
        buttons: ["OK"],
        style: .warning
    )
}

private func runCleanup(parentPID: pid_t, mount: URL, image: URL?, moveToTrash: Bool) {
    let executable = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
    let temporaryDirectory = fileManager.temporaryDirectory.standardizedFileURL
    guard executable.deletingLastPathComponent() == temporaryDirectory,
          executable.lastPathComponent.hasPrefix("sloosh-installer-cleanup-")
    else {
        return
    }

    let deadline = Date().addingTimeInterval(15)
    while parentPID > 0 && kill(parentPID, 0) == 0 && Date() < deadline {
        usleep(100_000)
    }
    if parentPID > 0 && kill(parentPID, 0) == 0 {
        showCleanupError("The installer could not finish closing, so the disk image remains mounted.")
        return
    }

    do {
        let result = try runProcess(
            URL(fileURLWithPath: "/usr/bin/hdiutil"),
            arguments: ["detach", mount.path]
        )
        guard result.0 == 0 else {
            showCleanupError("Installation finished, but the disk image could not be ejected.")
            return
        }
    } catch {
        showCleanupError("Installation finished, but the disk image could not be ejected: \(error.localizedDescription)")
        return
    }

    if moveToTrash, let image {
        do {
            guard image.pathExtension.lowercased() == "dmg" else {
                throw InstallerFailure.message("Refusing to trash a non-DMG file.")
            }
            var resultingURL: NSURL?
            try fileManager.trashItem(at: image, resultingItemURL: &resultingURL)
        } catch {
            showCleanupError("The disk image was ejected, but its DMG could not be moved to Trash: \(error.localizedDescription)")
        }
    }

    try? fileManager.removeItem(at: executable)
}

private func scheduleCleanup(mount: URL, image: URL?, moveToTrash: Bool) throws {
    let source = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
    let helper = fileManager.temporaryDirectory.appendingPathComponent(
        "sloosh-installer-cleanup-\(UUID().uuidString)"
    )
    try fileManager.copyItem(at: source, to: helper)
    try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)

    let process = Process()
    process.executableURL = helper
    process.arguments = [
        "--cleanup",
        String(getpid()),
        mount.path,
        image?.path ?? "",
        moveToTrash ? "1" : "0",
    ]
    process.currentDirectoryURL = fileManager.temporaryDirectory
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    do {
        try process.run()
    } catch {
        try? fileManager.removeItem(at: helper)
        throw error
    }
}

private func runInstallerUI() -> Int32 {
    NSApplication.shared.setActivationPolicy(.accessory)

    let installerBundle = Bundle.main.bundleURL
    let sourceApp = installerBundle.appendingPathComponent("Contents/Helpers/Sloosh.app")
    let applications = URL(fileURLWithPath: "/Applications", isDirectory: true)
    let home = fileManager.homeDirectoryForCurrentUser
    let target = applications.appendingPathComponent("Sloosh.app", isDirectory: true)
    let targetKind = try? nodeKind(at: target)
    let existing = targetKind != .missing
    let recognizedExisting = targetKind == .directory
        && (try? isRecognizedSlooshBundle(at: target)) == true
    let running = recognizedExisting && !runningTargetApplications(at: target).isEmpty
    let detail = running
        ? "Sloosh is running. Continuing will ask it to quit; if it does not close within 5 seconds, the installer will force quit it. Its daemon will also stop, ending active sessions and forwards."
        : existing
        ? "This replaces the installed app. If Sloosh starts before replacement, the installer will quit it and force quit after 5 seconds if needed. Its daemon will also stop, ending active sessions and forwards."
        : "Sloosh will be copied to Applications. Its CLI will be linked at ~/.local/bin/sloosh when that path is available."

    guard showAlert(
        title: running ? "Quit Sloosh and Update?" : existing ? "Replace Sloosh?" : "Install Sloosh?",
        message: detail,
        buttons: [running ? "Quit and Update" : existing ? "Replace" : "Install", "Cancel"],
        style: running ? .warning : .informational
    ) == .alertFirstButtonReturn else {
        return 0
    }

    let result: InstallResult
    do {
        result = try install(
            sourceApp: sourceApp,
            applicationsDirectory: applications,
            home: home,
            stopApplication: true,
            stopDaemon: true
        )
    } catch {
        _ = showAlert(
            title: "Installation Failed",
            message: error.localizedDescription,
            buttons: ["OK"],
            style: .critical
        )
        return 1
    }

    guard let mount = volumeRoot(containing: installerBundle) else {
        _ = showAlert(
            title: "Sloosh Installed",
            message: result.cliMessage,
            buttons: ["Done"]
        )
        return 0
    }

    let image = diskImageURL(for: mount)
    let response = showAlert(
        title: "Sloosh Installed",
        message: result.cliMessage + " The installer disk image will now be ejected.",
        buttons: image == nil ? ["Eject"] : ["Move DMG to Trash", "Keep DMG"]
    )
    let moveToTrash = image != nil && response == .alertFirstButtonReturn
    do {
        try scheduleCleanup(mount: mount, image: image, moveToTrash: moveToTrash)
    } catch {
        _ = showAlert(
            title: "Sloosh Installed",
            message: "Sloosh is installed, but automatic cleanup could not start: \(error.localizedDescription)",
            buttons: ["OK"],
            style: .warning
        )
        return 1
    }
    return 0
}

private func runTestingCommand(arguments: [String]) -> Int32? {
    guard arguments.count >= 2 else { return nil }
    if arguments[1].hasPrefix("--test-"),
       ProcessInfo.processInfo.environment["SLOOSH_INSTALLER_TEST_MODE"] != "1"
    {
        fputs("error: installer test command is disabled\n", stderr)
        return 2
    }
    switch arguments[1] {
    case "--test-install":
        guard arguments.count == 4 else {
            fputs("usage: install-sloosh --test-install <applications-dir> <home>\n", stderr)
            return 2
        }
        do {
            let result = try install(
                sourceApp: Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/Sloosh.app"),
                applicationsDirectory: URL(fileURLWithPath: arguments[2], isDirectory: true),
                home: URL(fileURLWithPath: arguments[3], isDirectory: true),
                stopApplication: false,
                stopDaemon: false
            )
            print("installed \(result.targetApp.path)")
            print(result.cliMessage)
            return 0
        } catch {
            fputs("error: \(error.localizedDescription)\n", stderr)
            return 1
        }
    case "--test-image-path":
        guard arguments.count == 3 else { return 2 }
        guard let image = diskImageURL(for: URL(fileURLWithPath: arguments[2], isDirectory: true)) else {
            return 1
        }
        print(image.path)
        return 0
    case "--test-shutdown":
        guard arguments.count == 3 else { return 2 }
        do {
            try stopExistingDaemon(home: URL(fileURLWithPath: arguments[2], isDirectory: true))
            return 0
        } catch {
            fputs("error: \(error.localizedDescription)\n", stderr)
            return 1
        }
    case "--test-stop-application":
        guard arguments.count == 3 else { return 2 }
        do {
            try stopRunningApplication(at: URL(fileURLWithPath: arguments[2], isDirectory: true))
            return 0
        } catch {
            fputs("error: \(error.localizedDescription)\n", stderr)
            return 1
        }
    case "--test-running-application-count":
        guard arguments.count == 3 else { return 2 }
        print(runningTargetApplications(
            at: URL(fileURLWithPath: arguments[2], isDirectory: true)
        ).count)
        return 0
    case "--test-cleanup":
        guard arguments.count == 3 else { return 2 }
        do {
            try scheduleCleanup(
                mount: URL(fileURLWithPath: arguments[2], isDirectory: true),
                image: nil,
                moveToTrash: false
            )
            return 0
        } catch {
            fputs("error: \(error.localizedDescription)\n", stderr)
            return 1
        }
    case "--cleanup":
        guard arguments.count == 6,
              let parent = Int32(arguments[2])
        else {
            return 2
        }
        let image = arguments[4].isEmpty ? nil : URL(fileURLWithPath: arguments[4])
        runCleanup(
            parentPID: parent,
            mount: URL(fileURLWithPath: arguments[3], isDirectory: true),
            image: image,
            moveToTrash: arguments[5] == "1"
        )
        return 0
    default:
        return nil
    }
}

let status = runTestingCommand(arguments: CommandLine.arguments) ?? runInstallerUI()
exit(status)
