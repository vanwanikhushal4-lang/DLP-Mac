import Foundation
import Security
import VeloxCore
import os.log

private struct ControlSnapshot: Codable {
    let ok: Bool
    let extensionStatus: String
    let policyVersion: Int
    let mode: String
    let blockedRuleCount: Int
    let blockedSigningIds: [String]
    let blockedExecutablePaths: [String]
    let webUploadMode: String
    let webUploadProtectedDirectories: [String]
    let usbStorageMode: String
    let totalAuthHandled: UInt64
    let totalDeadlineMisses: UInt64
    let message: String?
}

private struct EventsResponse: Codable {
    let ok: Bool
    let events: [ExecutionEvent]
    let message: String?
}

private struct ErrorResponse: Codable {
    let ok: Bool
    let message: String
}

private struct BrowserUploadAttempt: Decodable {
    let pageURL: String
    let fileNames: [String]
    let interaction: String
    let blocked: Bool
}

/// Rejects every caller except the valid, Team-ID-bound Velox host application.
/// PID lookup is performed while accepting the live connection, then both the
/// signature validity and immutable signing identity are checked.
final class VeloxControlPeerValidator {
    private let logger = Logger(subsystem: "co.velox.macdlp.endpointsecurity", category: "ControlAuth")

    func isAuthorized(_ connection: NSXPCConnection) -> Bool {
        let attributes = [
            kSecGuestAttributePid: NSNumber(value: connection.processIdentifier)
        ] as CFDictionary

        var dynamicCode: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &dynamicCode) == errSecSuccess,
              let dynamicCode else {
            logger.error("Rejected XPC PID \(connection.processIdentifier): unable to obtain code identity")
            return false
        }

        guard SecCodeCheckValidity(
            dynamicCode,
            SecCSFlags(rawValue: kSecCSStrictValidate),
            nil
        ) == errSecSuccess else {
            logger.error("Rejected XPC PID \(connection.processIdentifier): invalid code signature")
            return false
        }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(dynamicCode, [], &staticCode) == errSecSuccess,
              let staticCode else {
            logger.error("Rejected XPC PID \(connection.processIdentifier): unable to inspect static code")
            return false
        }

        var signingInformation: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &signingInformation
        ) == errSecSuccess,
              let values = signingInformation as? [String: Any] else {
            logger.error("Rejected XPC PID \(connection.processIdentifier): missing signing information")
            return false
        }

        let identifier = values[kSecCodeInfoIdentifier as String] as? String
        let teamIdentifier = values[kSecCodeInfoTeamIdentifier as String] as? String
        let accepted = identifier.map(VeloxControlConstants.authorizedControlBundleIdentifiers.contains) == true &&
            teamIdentifier == VeloxControlConstants.teamIdentifier

        if !accepted {
            logger.error(
                "Rejected XPC PID \(connection.processIdentifier): identifier=\(identifier ?? "missing", privacy: .public), team=\(teamIdentifier ?? "missing", privacy: .public)"
            )
        }
        return accepted
    }
}

final class VeloxControlListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let service: VeloxControlService
    private let validator = VeloxControlPeerValidator()

    init(service: VeloxControlService) {
        self.service = service
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard validator.isAuthorized(connection) else { return false }
        connection.exportedInterface = NSXPCInterface(with: VeloxControlProtocol.self)
        connection.exportedObject = service
        connection.remoteObjectInterface = NSXPCInterface(with: VeloxClientProtocol.self)
        service.addClient(connection)
        connection.invalidationHandler = { [weak service, weak connection] in
            if let connection {
                service?.removeClient(connection)
            }
        }
        connection.interruptionHandler = { [weak service, weak connection] in
            if let connection {
                service?.removeClient(connection)
            }
        }
        connection.resume()
        return true
    }
}

final class VeloxControlService: NSObject, VeloxControlProtocol, @unchecked Sendable {
    private let policyManager: PolicyManager
    private let healthPath: String
    private let logPath: String
    private let eventLogger: EventLogger
    private let mutationLock = NSLock()
    private let clientsLock = NSLock()
    private var connectedClients: [NSXPCConnection] = []
    private let logger = Logger(subsystem: "co.velox.macdlp.endpointsecurity", category: "ControlService")

    init(
        policyManager: PolicyManager,
        healthPath: String = "/Library/Application Support/VeloxMacDLP/health.json",
        logPath: String = EventLogger.defaultLogPath,
        eventLogger: EventLogger? = nil
    ) {
        self.policyManager = policyManager
        self.healthPath = healthPath
        self.logPath = logPath
        self.eventLogger = eventLogger ?? EventLogger(logFilePath: logPath)
    }

    func addClient(_ connection: NSXPCConnection) {
        clientsLock.lock()
        connectedClients.append(connection)
        clientsLock.unlock()
    }

    func removeClient(_ connection: NSXPCConnection) {
        clientsLock.lock()
        connectedClients.removeAll { $0 === connection }
        clientsLock.unlock()
    }

    func broadcastBlockedEvent(_ event: ExecutionEvent) {
        clientsLock.lock()
        let clients = connectedClients
        clientsLock.unlock()

        let module = event.module
        let action = event.action
        let target = event.resourcePath ?? event.executablePath
        let detail = event.signingId ?? event.teamId ?? ""
        let timestamp = Date().timeIntervalSince1970

        for client in clients {
            if let proxy = client.remoteObjectProxyWithErrorHandler({ _ in }) as? VeloxClientProtocol {
                proxy.handleBlockedEvent(
                    module: module,
                    action: action,
                    target: target,
                    detail: detail,
                    timestamp: timestamp
                )
            }
        }
    }

    func getSnapshot(withReply reply: @escaping (String) -> Void) {
        reply(snapshotJSON())
    }

    func setMode(_ mode: String, withReply reply: @escaping (String) -> Void) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        guard let requestedMode = PolicyMode(rawValue: mode) else {
            reply(errorJSON("Unsupported application-control mode '\(mode)'."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: ApplicationControlConfig(
                mode: requestedMode,
                blockedApplications: current.applicationControl.blockedApplications,
                allowedApplications: current.applicationControl.allowedApplications
            ),
            webUploadControl: current.webUploadControl,
            usbStorageControl: current.usbStorageControl
        )
        apply(updated, reply: reply)
    }

    func setWebUploadMode(_ mode: String, withReply reply: @escaping (String) -> Void) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        guard let requestedMode = PolicyMode(rawValue: mode) else {
            reply(errorJSON("Unsupported web-upload mode '\(mode)'."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: WebUploadControlConfig(
                mode: requestedMode,
                protectedDirectoryNames: current.webUploadControl.protectedDirectoryNames
            ),
            usbStorageControl: current.usbStorageControl
        )
        apply(updated, reply: reply)
    }

    func setUSBStorageMode(_ mode: String, withReply reply: @escaping (String) -> Void) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        guard let requestedMode = PolicyMode(rawValue: mode) else {
            reply(errorJSON("Unsupported usb-storage mode '\(mode)'."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            usbStorageControl: USBStorageControlConfig(
                mode: requestedMode,
                blockExternalStorage: current.usbStorageControl.blockExternalStorage
            )
        )
        apply(updated, reply: reply)
    }

    func recordBrowserUploadAttempt(_ payloadJSON: String, withReply reply: @escaping (String) -> Void) {
        guard let data = payloadJSON.data(using: .utf8), data.count <= 32_768,
              let attempt = try? JSONDecoder().decode(BrowserUploadAttempt.self, from: data) else {
            reply(errorJSON("Invalid browser-upload event."))
            return
        }

        let validInteractions = Set(["file-picker", "drag-drop", "paste", "form-submit"])
        let fileNames = attempt.fileNames.prefix(20).compactMap { raw -> String? in
            let name = (raw as NSString).lastPathComponent
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard !name.isEmpty, name.count <= 512 else { return nil }
            return name
        }
        guard !fileNames.isEmpty, validInteractions.contains(attempt.interaction) else {
            reply(errorJSON("Browser-upload event contains no valid files or interaction."))
            return
        }

        let policy = policyManager.policyEngine.currentPolicy()
        let decision: String
        switch policy.webUploadControl.mode {
        case .enforce: decision = attempt.blocked ? "blocked" : "enforcement-mismatch"
        case .auditOnly: decision = "would-block"
        case .disabled: decision = "allowed"
        }

        let pageURL = String(attempt.pageURL.prefix(2_048))
        let event = ExecutionEvent(
            module: "web-upload-control",
            action: "browser-upload-attempt",
            decision: decision,
            ruleId: "browser-extension-upload-guard",
            policyVersion: policy.policyVersion,
            executablePath: "Safari",
            signingId: VeloxControlConstants.safariUploadGuardBundleIdentifier,
            teamId: VeloxControlConstants.teamIdentifier,
            pid: 0,
            parentPid: 0,
            uid: 0,
            decisionLatencyMicros: 1,
            authResponseResult: "browser-boundary",
            resourcePath: fileNames.joined(separator: ", "),
            pageURL: pageURL,
            interaction: attempt.interaction
        )
        eventLogger.logEventSync(event)
        if decision == "blocked" {
            broadcastBlockedEvent(event)
        }
        reply(#"{"ok":true}"#)
    }

    func setApplicationBlocked(
        signingId: String,
        executablePath: String,
        displayName: String,
        blocked: Bool,
        withReply reply: @escaping (String) -> Void
    ) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        let normalizedSigningId = signingId.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedPath = executablePath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedSigningId.isEmpty || normalizedPath.hasPrefix("/") else {
            reply(errorJSON("A valid signing identity or absolute executable path is required."))
            return
        }

        if SecurityGuardian.selfSigningIdentifiers.contains(normalizedSigningId) ||
            SecurityGuardian.criticalSigningIdentifiers.contains(normalizedSigningId) {
            reply(errorJSON("\(displayName) is protected and cannot be blocked."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        var blockedRules = current.applicationControl.blockedApplications.filter { rule in
            let sameSigningId = !normalizedSigningId.isEmpty &&
                rule.signingId?.caseInsensitiveCompare(normalizedSigningId) == .orderedSame
            let samePath = !normalizedPath.isEmpty && rule.executablePath == normalizedPath
            return !sameSigningId && !samePath
        }

        if blocked {
            blockedRules.append(
                ApplicationRule(
                    ruleId: "console-\(UUID().uuidString.lowercased())",
                    signingId: normalizedSigningId.isEmpty ? nil : normalizedSigningId,
                    executablePath: normalizedSigningId.isEmpty ? normalizedPath : nil
                )
            )
        }

        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: ApplicationControlConfig(
                mode: current.applicationControl.mode,
                blockedApplications: blockedRules,
                allowedApplications: current.applicationControl.allowedApplications
            ),
            webUploadControl: current.webUploadControl,
            usbStorageControl: current.usbStorageControl
        )
        apply(updated, reply: reply)
    }

    func getRecentEvents(limit: Int, withReply reply: @escaping (String) -> Void) {
        let boundedLimit = min(max(limit, 1), 200)
        do {
            let text = try String(contentsOfFile: logPath, encoding: .utf8)
            let decoder = JSONDecoder()
            let events = text.split(separator: "\n")
                .suffix(boundedLimit)
                .compactMap { Data($0.utf8) }
                .compactMap { try? decoder.decode(ExecutionEvent.self, from: $0) }
            reply(encode(EventsResponse(ok: true, events: events, message: nil)))
        } catch {
            reply(errorJSON("Unable to read the activity log: \(error.localizedDescription)"))
        }
    }

    private func apply(_ policy: VeloxPolicy, reply: (String) -> Void) {
        do {
            try policyManager.applyPolicy(policy, persistToDisk: true)
            logger.info("Activated console policy version \(policy.policyVersion)")
            reply(snapshotJSON())
        } catch {
            logger.error("Policy mutation failed: \(String(describing: error), privacy: .public)")
            reply(errorJSON("Policy was not activated: \(error)"))
        }
    }

    private func snapshotJSON() -> String {
        let policy = policyManager.policyEngine.currentPolicy()
        let health = readHealth()
        return encode(
            ControlSnapshot(
                ok: true,
                extensionStatus: health?.status ?? "enforcing",
                policyVersion: policy.policyVersion,
                mode: policy.applicationControl.mode.rawValue,
                blockedRuleCount: policy.applicationControl.blockedApplications.count,
                blockedSigningIds: policy.applicationControl.blockedApplications
                    .compactMap(\.signingId)
                    .map { $0.lowercased() },
                blockedExecutablePaths: policy.applicationControl.blockedApplications.compactMap(\.executablePath),
                webUploadMode: policy.webUploadControl.mode.rawValue,
                webUploadProtectedDirectories: policy.webUploadControl.protectedDirectoryNames,
                usbStorageMode: policy.usbStorageControl.mode.rawValue,
                totalAuthHandled: health?.totalAuthHandled ?? 0,
                totalDeadlineMisses: health?.totalDeadlineMisses ?? 0,
                message: nil
            )
        )
    }

    private func readHealth() -> HealthStatus? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: healthPath)) else { return nil }
        return try? JSONDecoder().decode(HealthStatus.self, from: data)
    }

    private func errorJSON(_ message: String) -> String {
        encode(ErrorResponse(ok: false, message: message))
    }

    private func encode<T: Encodable>(_ value: T) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(value),
              let result = String(data: data, encoding: .utf8) else {
            return #"{"ok":false,"message":"Response encoding failed."}"#
        }
        return result
    }
}
