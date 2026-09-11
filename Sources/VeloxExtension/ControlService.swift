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
    let emailAttachmentMode: String
    let emailClientCount: Int
    let emailClientSigningIds: [String]
    let emailProtectedClassifications: [String]
    let emailCachedClassificationCount: Int
    let usbStorageMode: String
    let usbEncryptionMode: String
    let usbContainerSizePercent: Int
    let usbExternalVolumeCount: Int
    let usbEncryptedContainerCount: Int
    let usbEncryptionLastError: String?
    let nearbyTransferMode: String
    let nearbyTransferProtectedDirectories: [String]
    let nearbyTransferBlocksAirDrop: Bool
    let nearbyTransferBlocksBluetooth: Bool
    let clipboardMode: String
    let clipboardBlockedRuleCount: Int
    let clipboardBlockedSigningIds: [String]
    let clipboardBlockedExecutablePaths: [String]
    let printerMode: String
    let printerQueueCount: Int
    let printerControlledQueueCount: Int
    let printerLastError: String?
    let ocrMode: String
    let screenshotOCRMode: String
    let screenshotOCRRemediation: String
    let ocrRuleCount: Int
    let ocrRecognitionLanguages: [String]
    let ocrClassifications: [String]
    let endpointDiscoveryMode: String
    let endpointDiscoveryScheduleIntervalMinutes: Int
    let endpointDiscoveryIncludesLocalHome: Bool
    let endpointDiscoveryIncludesMountedVolumes: Bool
    let endpointDiscoveryIncludesMountedShares: Bool
    let endpointDiscoveryTagsClassifiedFiles: Bool
    let endpointDiscoveryMaxFilesPerScan: Int
    let networkFlowMode: String
    let cloudSyncMode: String
    let opticalDiskImageMode: String
    let opticalDiskImageBlocksDiskImages: Bool
    let opticalDiskImageBlocksOpticalMedia: Bool
    let screenWatermarkingMode: String
    let printToPDFMode: String
    let networkFlowDefaultAction: String
    let networkFlowRuleCount: Int
    let networkFlowRules: [NetworkDestinationRule]
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

private struct ClipboardEventAttempt: Decodable {
    let sourceApplication: String
    let signingId: String?
    let teamId: String?
    let executablePath: String
    let pid: Int32
    let codesigningFlags: UInt32
    let isPlatformBinary: Bool
    let contentTypes: [String]
    let itemCount: Int
    let cleared: Bool
}

private struct OCRScanEventAttempt: Decodable {
    let source: String
    let fileType: String
    let contentHashPrefix: String
    let decision: String
    let ruleIds: [String]
    let classifications: [String]
    let recognizedCharacterCount: Int
    let pageCount: Int
    let averageConfidence: Double
    let usedOCR: Bool
    let cacheHit: Bool
    let durationMillis: Int
    let remediation: String
}

private struct EndpointDiscoveryEventAttempt: Decodable {
    let kind: String
    let scanId: String
    let trigger: String
    let filePath: String?
    let fileType: String?
    let contentHashPrefix: String?
    let locationKind: String?
    let ruleIds: [String]
    let classifications: [String]
    let tagStatus: String?
    let durationMillis: Int
    let filesEnumerated: Int?
    let filesInspected: Int?
    let findingsCount: Int?
    let taggedCount: Int?
    let inaccessibleItems: Int?
    let status: String?
    let fileSize: Int64?
    let modifiedAtSeconds: Int64?
    let modifiedAtNanoseconds: Int64?
}

/// Resolves each valid, Team-ID-bound Velox caller to its least-privilege role.
/// PID lookup is performed while accepting the live connection, then both the
/// signature validity and immutable signing identity are checked.
enum VeloxControlPeerRole {
    case fullControl
    case networkEventSink
}

final class VeloxControlPeerValidator {
    private let logger = Logger(subsystem: "co.velox.macdlp.endpointsecurity", category: "ControlAuth")

    func role(for connection: NSXPCConnection) -> VeloxControlPeerRole? {
        let attributes = [
            kSecGuestAttributePid: NSNumber(value: connection.processIdentifier)
        ] as CFDictionary

        var dynamicCode: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &dynamicCode) == errSecSuccess,
              let dynamicCode else {
            logger.error("Rejected XPC PID \(connection.processIdentifier): unable to obtain code identity")
            return nil
        }

        guard SecCodeCheckValidity(
            dynamicCode,
            SecCSFlags(rawValue: kSecCSStrictValidate),
            nil
        ) == errSecSuccess else {
            logger.error("Rejected XPC PID \(connection.processIdentifier): invalid code signature")
            return nil
        }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(dynamicCode, [], &staticCode) == errSecSuccess,
              let staticCode else {
            logger.error("Rejected XPC PID \(connection.processIdentifier): unable to inspect static code")
            return nil
        }

        var signingInformation: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &signingInformation
        ) == errSecSuccess,
              let values = signingInformation as? [String: Any] else {
            logger.error("Rejected XPC PID \(connection.processIdentifier): missing signing information")
            return nil
        }

        let identifier = values[kSecCodeInfoIdentifier as String] as? String
        let teamIdentifier = values[kSecCodeInfoTeamIdentifier as String] as? String
        guard teamIdentifier == VeloxControlConstants.teamIdentifier else {
            logger.error(
                "Rejected XPC PID \(connection.processIdentifier): identifier=\(identifier ?? "missing", privacy: .public), team=\(teamIdentifier ?? "missing", privacy: .public)"
            )
            return nil
        }

        if identifier.map(VeloxControlConstants.authorizedControlBundleIdentifiers.contains) == true {
            return .fullControl
        }
        if identifier == VeloxControlConstants.networkFilterBundleIdentifier {
            return .networkEventSink
        }

        logger.error(
            "Rejected XPC PID \(connection.processIdentifier): unauthorized identifier=\(identifier ?? "missing", privacy: .public)"
        )
        return nil
    }
}

final class VeloxControlListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let service: VeloxControlService
    private let validator = VeloxControlPeerValidator()

    init(service: VeloxControlService) {
        self.service = service
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard let role = validator.role(for: connection) else { return false }
        switch role {
        case .fullControl:
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
        case .networkEventSink:
            connection.exportedInterface = NSXPCInterface(with: VeloxNetworkEventSinkProtocol.self)
            connection.exportedObject = service
        }
        connection.resume()
        return true
    }
}

final class VeloxControlService: NSObject, VeloxControlProtocol, VeloxNetworkEventSinkProtocol, @unchecked Sendable {
    private let policyManager: PolicyManager
    private let healthPath: String
    private let logPath: String
    private let eventLogger: EventLogger
    private let usbEncryptionCoordinator: USBEncryptionCoordinator
    private let printerCoordinator: PrinterControlCoordinator
    private let classificationCache: FileClassificationCache
    private let mutationLock = NSLock()
    private let clientsLock = NSLock()
    private var connectedClients: [NSXPCConnection] = []
    private let logger = Logger(subsystem: "co.velox.macdlp.endpointsecurity", category: "ControlService")

    init(
        policyManager: PolicyManager,
        healthPath: String = "/Library/Application Support/VeloxMacDLP/health.json",
        logPath: String = EventLogger.defaultLogPath,
        eventLogger: EventLogger? = nil,
        usbEncryptionCoordinator: USBEncryptionCoordinator,
        printerCoordinator: PrinterControlCoordinator,
        classificationCache: FileClassificationCache = FileClassificationCache()
    ) {
        self.policyManager = policyManager
        self.healthPath = healthPath
        self.logPath = logPath
        self.eventLogger = eventLogger ?? EventLogger(logFilePath: logPath)
        self.usbEncryptionCoordinator = usbEncryptionCoordinator
        self.printerCoordinator = printerCoordinator
        self.classificationCache = classificationCache
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
        let detail: String
        if event.module == "clipboard-control" {
            detail = event.pageURL ?? event.signingId ?? "Application"
        } else if event.module == "ocr-content-classification" {
            detail = event.classifications?.joined(separator: ", ") ?? ""
        } else if event.module == "email-attachment-control" {
            detail = "\(event.interaction ?? event.signingId ?? "Mail client")|\(event.classifications?.joined(separator: ", ") ?? "Classified content")"
        } else if event.module == "network-flow-control" {
            detail = event.executablePath
        } else {
            detail = event.signingId ?? event.teamId ?? ""
        }
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

    func broadcastPotentialScreenshot(path: String) {
        clientsLock.lock()
        let clients = connectedClients
        clientsLock.unlock()
        let timestamp = Date().timeIntervalSince1970
        for client in clients {
            if let proxy = client.remoteObjectProxyWithErrorHandler({ _ in }) as? VeloxClientProtocol {
                proxy.handlePotentialScreenshot(path: path, timestamp: timestamp)
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
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: current.networkFlowControl,
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
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
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: current.networkFlowControl,
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
        )
        apply(updated, reply: reply)
    }

    func setEmailAttachmentConfig(_ configJSON: String, withReply reply: @escaping (String) -> Void) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        let validKeys: Set<String> = ["mode", "mailClients", "protectedClassifications"]
        let validRuleKeys: Set<String> = [
            "ruleId", "signingId", "teamId", "isPlatformBinary",
            "cdhash", "executablePath", "executablePathPrefix"
        ]
        guard let data = configJSON.data(using: .utf8), data.count <= 65_536,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              object.keys.allSatisfy(validKeys.contains),
              let clients = object["mailClients"] as? [[String: Any]],
              clients.allSatisfy({ $0.keys.allSatisfy(validRuleKeys.contains) }),
              let requested = try? JSONDecoder().decode(EmailAttachmentControlConfig.self, from: data) else {
            reply(errorJSON("Invalid Email Attachment Control configuration."))
            return
        }
        do {
            try requested.validate()
        } catch {
            reply(errorJSON("Email Attachment Control configuration was rejected: \(error)"))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            emailAttachmentControl: requested,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: current.networkFlowControl,
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
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
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: USBStorageControlConfig(
                mode: requestedMode,
                blockExternalStorage: current.usbStorageControl.blockExternalStorage,
                encryptionMode: requestedMode == .disabled
                    ? current.usbStorageControl.encryptionMode
                    : .disabled,
                containerSizePercent: current.usbStorageControl.containerSizePercent
            ),
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: current.networkFlowControl,
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
        )
        apply(updated, reply: reply)
    }

    func setUSBEncryptionMode(_ mode: String, withReply reply: @escaping (String) -> Void) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        guard let requestedMode = PolicyMode(rawValue: mode) else {
            reply(errorJSON("Unsupported USB encryption mode '\(mode)'."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: USBStorageControlConfig(
                mode: requestedMode == .disabled ? current.usbStorageControl.mode : .disabled,
                blockExternalStorage: current.usbStorageControl.blockExternalStorage,
                encryptionMode: requestedMode,
                containerSizePercent: current.usbStorageControl.containerSizePercent
            ),
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: current.networkFlowControl,
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
        )
        apply(updated, reply: reply)
    }

    func setNearbyTransferMode(_ mode: String, withReply reply: @escaping (String) -> Void) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        guard let requestedMode = PolicyMode(rawValue: mode) else {
            reply(errorJSON("Unsupported nearby-transfer mode '\(mode)'."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: NearbyTransferControlConfig(
                mode: requestedMode,
                blockAirDrop: current.nearbyTransferControl.blockAirDrop,
                blockBluetoothFileTransfer: current.nearbyTransferControl.blockBluetoothFileTransfer,
                protectedDirectoryNames: current.nearbyTransferControl.protectedDirectoryNames
            ),
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: current.networkFlowControl,
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
        )
        apply(updated, reply: reply)
    }

    func setClipboardMode(_ mode: String, withReply reply: @escaping (String) -> Void) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        guard let requestedMode = ClipboardControlMode(rawValue: mode) else {
            reply(errorJSON("Unsupported clipboard-control mode '\(mode)'."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: ClipboardControlConfig(
                mode: requestedMode,
                blockedApplications: current.clipboardControl.blockedApplications
            ),
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: current.networkFlowControl,
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
        )
        apply(updated, reply: reply)
    }

    func setPrinterMode(_ mode: String, withReply reply: @escaping (String) -> Void) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        guard let requestedMode = PolicyMode(rawValue: mode) else {
            reply(errorJSON("Unsupported printer-control mode '\(mode)'."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: PrinterControlConfig(
                mode: requestedMode,
                blockAllPrinters: current.printerControl.blockAllPrinters
            ),
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: current.networkFlowControl,
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
        )
        apply(updated, reply: reply)
    }

    func setOCRMode(_ mode: String, withReply reply: @escaping (String) -> Void) {
        mutateOCRConfig(mode: mode, updatesScreenshotMode: false, reply: reply)
    }

    func setScreenshotOCRMode(_ mode: String, withReply reply: @escaping (String) -> Void) {
        mutateOCRConfig(mode: mode, updatesScreenshotMode: true, reply: reply)
    }

    func setEndpointDiscoveryConfig(_ configJSON: String, withReply reply: @escaping (String) -> Void) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        let validKeys: Set<String> = [
            "mode", "scheduleIntervalMinutes", "includeLocalHome",
            "includeMountedVolumes", "includeMountedShares",
            "tagClassifiedFiles", "maxFilesPerScan"
        ]
        guard let data = configJSON.data(using: .utf8), data.count <= 32_768,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              object.keys.allSatisfy(validKeys.contains),
              let requested = try? JSONDecoder().decode(
                EndpointDiscoveryControlConfig.self,
                from: data
              ) else {
            reply(errorJSON("Invalid Endpoint Data Discovery configuration."))
            return
        }
        do {
            try requested.validate()
        } catch {
            reply(errorJSON("Endpoint Data Discovery configuration was rejected: \(error)"))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: requested,
            networkFlowControl: current.networkFlowControl,
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
        )
        apply(updated, reply: reply)
    }

    private func mutateOCRConfig(
        mode: String,
        updatesScreenshotMode: Bool,
        reply: @escaping (String) -> Void
    ) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        guard let requestedMode = PolicyMode(rawValue: mode) else {
            reply(errorJSON("Unsupported OCR mode '\(mode)'."))
            return
        }
        let current = policyManager.policyEngine.currentPolicy()
        let ocr = current.ocrControl
        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: OCRControlConfig(
                mode: updatesScreenshotMode ? ocr.mode : requestedMode,
                screenshotMode: updatesScreenshotMode ? requestedMode : ocr.screenshotMode,
                screenshotRemediation: ocr.screenshotRemediation,
                recognitionLanguages: ocr.recognitionLanguages,
                minimumConfidence: ocr.minimumConfidence,
                maxFileSizeMB: ocr.maxFileSizeMB,
                maxPDFPages: ocr.maxPDFPages,
                rules: ocr.rules
            ),
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: current.networkFlowControl,
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
        )
        apply(updated, reply: reply)
    }


    func setCloudSyncMode(_ mode: String, withReply reply: @escaping (String) -> Void) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        guard let requestedMode = PolicyMode(rawValue: mode) else {
            reply(errorJSON("Unsupported cloud-sync mode '\(mode)'."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: current.networkFlowControl,
            cloudSyncControl: CloudSyncControlConfig(
                mode: requestedMode,
                blockCloudSync: current.cloudSyncControl.blockCloudSync,
                monitoredProviders: current.cloudSyncControl.monitoredProviders
            ),
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
        )
        apply(updated, reply: reply)
    }

    func setOpticalDiskImageMode(_ mode: String, withReply reply: @escaping (String) -> Void) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        guard let requestedMode = PolicyMode(rawValue: mode) else {
            reply(errorJSON("Unsupported optical-disk-image mode '\(mode)'."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: current.networkFlowControl,
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: OpticalDiskImageControlConfig(
                mode: requestedMode,
                blockDiskImages: current.opticalDiskImageControl.blockDiskImages,
                blockOpticalMedia: current.opticalDiskImageControl.blockOpticalMedia
            ),
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
        )
        apply(updated, reply: reply)
    }

    func setOpticalDiskImageConfig(
        _ configJSON: String,
        withReply reply: @escaping (String) -> Void
    ) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        let validKeys: Set<String> = ["mode", "blockDiskImages", "blockOpticalMedia"]
        guard let data = configJSON.data(using: .utf8), data.count <= 16_384,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              object.keys.allSatisfy(validKeys.contains),
              let requested = try? JSONDecoder().decode(
                  OpticalDiskImageControlConfig.self,
                  from: data
              ),
              (try? requested.validate()) != nil else {
            reply(errorJSON("Invalid Optical & Disk Image Control configuration."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: current.networkFlowControl,
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: requested,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
        )
        apply(updated, reply: reply)
    }

    func setScreenWatermarkingMode(_ mode: String, withReply reply: @escaping (String) -> Void) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        guard let requestedMode = PolicyMode(rawValue: mode) else {
            reply(errorJSON("Unsupported screen-watermarking mode '\(mode)'."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: current.networkFlowControl,
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: ScreenWatermarkingConfig(
                mode: requestedMode,
                text: current.screenWatermarking.text,
                opacity: current.screenWatermarking.opacity
            ),
            printToPDFControl: current.printToPDFControl
        )
        apply(updated, reply: reply)
    }

    func setPrintToPDFMode(_ mode: String, withReply reply: @escaping (String) -> Void) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        guard let requestedMode = PolicyMode(rawValue: mode) else {
            reply(errorJSON("Unsupported print-to-pdf mode '\(mode)'."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: current.networkFlowControl,
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: PrintToPDFControlConfig(
                mode: requestedMode,
                blockSaveAsPDF: current.printToPDFControl.blockSaveAsPDF
            )
        )
        apply(updated, reply: reply)
    }

    func setNetworkFlowMode(_ mode: String, withReply reply: @escaping (String) -> Void) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        guard let requestedMode = PolicyMode(rawValue: mode) else {
            reply(errorJSON("Unsupported network-flow mode '\(mode)'."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: NetworkFlowControlConfig(
                mode: requestedMode,
                defaultAction: current.networkFlowControl.defaultAction,
                rules: current.networkFlowControl.rules
            ),
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
        )
        apply(updated, reply: reply)
    }

    func setNetworkFlowDefaultAction(_ action: String, withReply reply: @escaping (String) -> Void) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        guard let requestedAction = NetworkDefaultAction(rawValue: action) else {
            reply(errorJSON("Unsupported network-flow default action '\(action)'."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: NetworkFlowControlConfig(
                mode: current.networkFlowControl.mode,
                defaultAction: requestedAction,
                rules: current.networkFlowControl.rules
            ),
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
        )
        apply(updated, reply: reply)
    }

    func addNetworkFlowRule(_ ruleJSON: String, withReply reply: @escaping (String) -> Void) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        guard let data = ruleJSON.data(using: .utf8),
              let rule = try? JSONDecoder().decode(NetworkDestinationRule.self, from: data) else {
            reply(errorJSON("Invalid network flow rule JSON format."))
            return
        }

        let ruleId = rule.ruleId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !ruleId.isEmpty else {
            reply(errorJSON("Network flow rule ID cannot be empty."))
            return
        }
        guard rule.action == "allow" || rule.action == "block" else {
            reply(errorJSON("Network flow rule action must be 'allow' or 'block'."))
            return
        }
        guard rule.domain != nil || rule.ipAddress != nil || rule.cidrRange != nil || rule.port != nil || rule.portRange != nil || rule.protocol != .any || rule.process != nil else {
            reply(errorJSON("Network flow rule must specify at least one criteria (domain, IP, CIDR, port, protocol, or process)."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        var rules = current.networkFlowControl.rules.filter { $0.ruleId != ruleId }
        rules.append(rule)

        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: NetworkFlowControlConfig(
                mode: current.networkFlowControl.mode,
                defaultAction: current.networkFlowControl.defaultAction,
                rules: rules
            ),
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
        )
        apply(updated, reply: reply)
    }

    func removeNetworkFlowRule(ruleId: String, withReply reply: @escaping (String) -> Void) {
        mutationLock.lock()
        defer { mutationLock.unlock() }

        let targetId = ruleId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !targetId.isEmpty else {
            reply(errorJSON("Network flow rule ID cannot be empty."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        let rules = current.networkFlowControl.rules.filter { $0.ruleId != targetId }

        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: NetworkFlowControlConfig(
                mode: current.networkFlowControl.mode,
                defaultAction: current.networkFlowControl.defaultAction,
                rules: rules
            ),
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
        )
        apply(updated, reply: reply)
    }

    func setClipboardApplicationBlocked(
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

        if SecurityGuardian.selfSigningIdentifiers.contains(normalizedSigningId) {
            reply(errorJSON("\(displayName) is protected and cannot be clipboard-blocked."))
            return
        }

        let current = policyManager.policyEngine.currentPolicy()
        var blockedRules = current.clipboardControl.blockedApplications.filter { rule in
            let sameSigningId = !normalizedSigningId.isEmpty &&
                rule.signingId?.caseInsensitiveCompare(normalizedSigningId) == .orderedSame
            let samePath = !normalizedPath.isEmpty && rule.executablePath == normalizedPath
            return !sameSigningId && !samePath
        }

        if blocked {
            blockedRules.append(
                ApplicationRule(
                    ruleId: "clipboard-console-\(UUID().uuidString.lowercased())",
                    signingId: normalizedSigningId.isEmpty ? nil : normalizedSigningId,
                    executablePath: normalizedSigningId.isEmpty ? normalizedPath : nil
                )
            )
        }

        let updated = VeloxPolicy(
            policyVersion: current.policyVersion + 1,
            applicationControl: current.applicationControl,
            webUploadControl: current.webUploadControl,
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: ClipboardControlConfig(
                mode: current.clipboardControl.mode,
                blockedApplications: blockedRules
            ),
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: current.networkFlowControl,
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
        )
        apply(updated, reply: reply)
    }

    func recordClipboardEvent(_ payloadJSON: String, withReply reply: @escaping (String) -> Void) {
        guard let data = payloadJSON.data(using: .utf8), data.count <= 32_768,
              let attempt = try? JSONDecoder().decode(ClipboardEventAttempt.self, from: data) else {
            reply(errorJSON("Invalid clipboard event."))
            return
        }

        let sourceApplication = attempt.sourceApplication
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let executablePath = attempt.executablePath
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !sourceApplication.isEmpty,
              sourceApplication.count <= 256,
              executablePath.hasPrefix("/"),
              executablePath.count <= 4_096,
              (0...100).contains(attempt.itemCount) else {
            reply(errorJSON("Clipboard event contains invalid source metadata."))
            return
        }

        let sanitizedTypes = attempt.contentTypes.prefix(12).compactMap { raw -> String? in
            let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !value.isEmpty, value.count <= 64 else { return nil }
            return value
        }
        guard !sanitizedTypes.isEmpty else {
            reply(errorJSON("Clipboard event contains no valid data types."))
            return
        }

        let process = ProcessContext(
            pid: attempt.pid,
            parentPid: 0,
            uid: 0,
            signingId: attempt.signingId,
            teamId: attempt.teamId,
            isPlatformBinary: attempt.isPlatformBinary,
            cdhash: nil,
            executablePath: executablePath,
            codesigningFlags: attempt.codesigningFlags
        )
        let evaluated = policyManager.policyEngine.evaluateClipboardCopy(source: process)
        let decision = evaluated.shouldClearPasteboard
            ? (attempt.cleared ? "blocked" : "enforcement-mismatch")
            : "allowed"
        let summary = "\(sanitizedTypes.joined(separator: ", ")) · \(attempt.itemCount) item\(attempt.itemCount == 1 ? "" : "s")"
        let event = ExecutionEvent(
            module: "clipboard-control",
            action: "copy",
            decision: decision,
            ruleId: evaluated.matchingRuleId,
            policyVersion: evaluated.policyVersion,
            executablePath: executablePath,
            signingId: attempt.signingId,
            teamId: attempt.teamId,
            pid: attempt.pid,
            parentPid: 0,
            uid: 0,
            decisionLatencyMicros: 1,
            authResponseResult: attempt.cleared ? "pasteboard-cleared" : "pasteboard-observed",
            resourcePath: summary,
            pageURL: sourceApplication,
            interaction: "copy"
        )
        eventLogger.logEventSync(event)
        if decision == "blocked" {
            broadcastBlockedEvent(event)
        }
        reply(#"{"ok":true}"#)
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

    func recordOCRScanEvent(_ payloadJSON: String, withReply reply: @escaping (String) -> Void) {
        guard let data = payloadJSON.data(using: .utf8), data.count <= 32_768,
              let attempt = try? JSONDecoder().decode(OCRScanEventAttempt.self, from: data) else {
            reply(errorJSON("Invalid OCR event."))
            return
        }

        let validSources = Set(["manual", "screenshot", "discovery", "egress"])
        let validDecisions = Set(["allowed", "would-block", "blocked"])
        let validRemediations = Set(["none", "quarantined", "deleted", "remediation-failed"])
        guard validSources.contains(attempt.source),
              validDecisions.contains(attempt.decision),
              validRemediations.contains(attempt.remediation),
              !attempt.fileType.isEmpty,
              attempt.fileType.count <= 128,
              attempt.contentHashPrefix.count == 12,
              attempt.contentHashPrefix.allSatisfy(\.isHexDigit),
              (0...OCRClassifier.maximumInputCharacters).contains(attempt.recognizedCharacterCount),
              (1...500).contains(attempt.pageCount),
              (0...1).contains(attempt.averageConfidence),
              (0...600_000).contains(attempt.durationMillis),
              attempt.ruleIds.count <= 100,
              attempt.classifications.count <= 100 else {
            reply(errorJSON("OCR event contains invalid metadata."))
            return
        }

        let ruleIds = attempt.ruleIds.compactMap { value -> String? in
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return !trimmed.isEmpty && trimmed.count <= 256 ? trimmed : nil
        }
        guard ruleIds.count == attempt.ruleIds.count,
              attempt.classifications.count == attempt.ruleIds.count else {
            reply(errorJSON("OCR event contains invalid classification metadata."))
            return
        }

        let policy = policyManager.policyEngine.currentPolicy()
        let configuredRules = Dictionary(
            uniqueKeysWithValues: policy.ocrControl.rules.map { ($0.ruleId, $0.classification) }
        )
        let classifications = ruleIds.compactMap { configuredRules[$0] }
        guard classifications.count == ruleIds.count,
              zip(classifications, attempt.classifications).allSatisfy({ expected, supplied in
                  expected == supplied.trimmingCharacters(in: .whitespacesAndNewlines)
              }) else {
            reply(errorJSON("OCR event references a rule outside the active policy."))
            return
        }
        let expectedMode = attempt.source == "screenshot"
            ? policy.ocrControl.screenshotMode
            : policy.ocrControl.mode
        let expectedDecision: String
        if ruleIds.isEmpty || expectedMode == .disabled {
            expectedDecision = "allowed"
        } else if expectedMode == .auditOnly {
            expectedDecision = "would-block"
        } else {
            expectedDecision = "blocked"
        }
        guard attempt.decision == expectedDecision else {
            reply(errorJSON("OCR event decision does not match active policy."))
            return
        }

        let event = ExecutionEvent(
            module: "ocr-content-classification",
            action: attempt.source == "screenshot" ? "screenshot-scan" : "file-scan",
            decision: expectedDecision,
            ruleId: ruleIds.first,
            policyVersion: policy.policyVersion,
            executablePath: "/Applications/VeloxMacDLP.app/Contents/MacOS/VeloxMacDLP",
            signingId: VeloxControlConstants.hostBundleIdentifier,
            teamId: VeloxControlConstants.teamIdentifier,
            pid: 0,
            parentPid: 0,
            uid: 0,
            decisionLatencyMicros: UInt64(attempt.durationMillis) * 1_000,
            authResponseResult: attempt.usedOCR ? "vision-on-device" : "embedded-pdf-text",
            resourcePath: attempt.fileType,
            interaction: attempt.remediation,
            contentHashPrefix: attempt.contentHashPrefix.lowercased(),
            fileType: attempt.fileType,
            classifications: classifications,
            recognizedCharacterCount: attempt.recognizedCharacterCount,
            ocrConfidence: attempt.averageConfidence,
            pageCount: attempt.pageCount
        )
        eventLogger.logEventSync(event)
        if expectedDecision == "blocked" {
            broadcastBlockedEvent(event)
        }
        reply(#"{"ok":true}"#)
    }

    func recordEndpointDiscoveryEvent(_ payloadJSON: String, withReply reply: @escaping (String) -> Void) {
        guard let data = payloadJSON.data(using: .utf8), data.count <= 65_536,
              let attempt = try? JSONDecoder().decode(EndpointDiscoveryEventAttempt.self, from: data),
              ["finding", "summary"].contains(attempt.kind),
              ["manual", "scheduled"].contains(attempt.trigger),
              UUID(uuidString: attempt.scanId) != nil,
              (0...604_800_000).contains(attempt.durationMillis) else {
            reply(errorJSON("Invalid Endpoint Data Discovery event."))
            return
        }

        let policy = policyManager.policyEngine.currentPolicy()
        guard policy.endpointDiscoveryControl.mode != .disabled else {
            reply(errorJSON("Endpoint Data Discovery is disabled in the active policy."))
            return
        }

        if attempt.kind == "finding" {
            let validLocationKinds = Set(["local-home", "mounted-volume", "mounted-share"])
            let validTagStatuses = Set(["tagged", "audited", "tag-failed"])
            guard let path = attempt.filePath,
                  path.hasPrefix("/"), path.count <= 4_096,
                  !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
                  let fileType = attempt.fileType,
                  !fileType.isEmpty, fileType.count <= 128,
                  let hash = attempt.contentHashPrefix,
                  hash.count == 12, hash.allSatisfy(\.isHexDigit),
                  let locationKind = attempt.locationKind,
                  validLocationKinds.contains(locationKind),
                  let tagStatus = attempt.tagStatus,
                  validTagStatuses.contains(tagStatus),
                  !attempt.ruleIds.isEmpty,
                  attempt.ruleIds.count <= 100,
                  attempt.classifications.count == attempt.ruleIds.count else {
                reply(errorJSON("Endpoint Data Discovery finding contains invalid metadata."))
                return
            }

            let configuredRules = Dictionary(
                uniqueKeysWithValues: policy.ocrControl.rules.map { ($0.ruleId, $0.classification) }
            )
            let expectedClassifications = attempt.ruleIds.compactMap { configuredRules[$0] }
            guard expectedClassifications.count == attempt.ruleIds.count,
                  zip(expectedClassifications, attempt.classifications).allSatisfy({ expected, supplied in
                      expected == supplied.trimmingCharacters(in: .whitespacesAndNewlines)
                  }) else {
                reply(errorJSON("Endpoint Data Discovery finding references a rule outside the active policy."))
                return
            }

            let expectedTagStatuses: Set<String>
            if policy.endpointDiscoveryControl.mode == .enforce &&
                policy.endpointDiscoveryControl.tagClassifiedFiles {
                expectedTagStatuses = ["tagged", "tag-failed"]
            } else {
                expectedTagStatuses = ["audited"]
            }
            guard expectedTagStatuses.contains(tagStatus) else {
                reply(errorJSON("Endpoint Data Discovery tag status does not match the active policy."))
                return
            }

            let event = ExecutionEvent(
                module: "endpoint-data-discovery",
                action: "classified-file",
                decision: tagStatus == "tagged" ? "tagged" : tagStatus == "tag-failed" ? "tag-failed" : "detected",
                ruleId: attempt.ruleIds.first,
                policyVersion: policy.policyVersion,
                executablePath: "/Applications/VeloxMacDLP.app/Contents/MacOS/VeloxMacDLP",
                signingId: VeloxControlConstants.hostBundleIdentifier,
                teamId: VeloxControlConstants.teamIdentifier,
                pid: 0,
                parentPid: 0,
                uid: 0,
                decisionLatencyMicros: UInt64(attempt.durationMillis) * 1_000,
                authResponseResult: "scheduled-at-rest-scan",
                resourcePath: path,
                interaction: "\(locationKind):\(tagStatus)",
                contentHashPrefix: hash.lowercased(),
                fileType: fileType,
                classifications: expectedClassifications
            )
            eventLogger.logEventSync(event)
            if let fileSize = attempt.fileSize,
               let seconds = attempt.modifiedAtSeconds,
               let nanoseconds = attempt.modifiedAtNanoseconds,
               fileSize >= 0,
               seconds >= 0,
               (0..<1_000_000_000).contains(nanoseconds) {
                classificationCache.upsert([FileClassificationRecord(
                    filePath: path,
                    fileSize: fileSize,
                    modifiedAtSeconds: seconds,
                    modifiedAtNanoseconds: nanoseconds,
                    contentHashPrefix: hash.lowercased(),
                    classifications: expectedClassifications,
                    ruleIds: attempt.ruleIds,
                    policyVersion: policy.policyVersion
                )])
            }
        } else {
            let maxFiles = policy.endpointDiscoveryControl.maxFilesPerScan
            guard let filesEnumerated = attempt.filesEnumerated,
                  let filesInspected = attempt.filesInspected,
                  let findingsCount = attempt.findingsCount,
                  let taggedCount = attempt.taggedCount,
                  let inaccessibleItems = attempt.inaccessibleItems,
                  let status = attempt.status,
                  ["completed", "report-failed"].contains(status),
                  (0...maxFiles).contains(filesEnumerated),
                  (0...filesEnumerated).contains(filesInspected),
                  (0...filesInspected).contains(findingsCount),
                  (0...findingsCount).contains(taggedCount),
                  inaccessibleItems >= 0 else {
                reply(errorJSON("Endpoint Data Discovery summary contains invalid counters."))
                return
            }
            let summary = "enumerated=\(filesEnumerated);inspected=\(filesInspected);findings=\(findingsCount);tagged=\(taggedCount);inaccessible=\(inaccessibleItems)"
            let event = ExecutionEvent(
                module: "endpoint-data-discovery",
                action: "scan-completed",
                decision: status,
                ruleId: nil,
                policyVersion: policy.policyVersion,
                executablePath: "/Applications/VeloxMacDLP.app/Contents/MacOS/VeloxMacDLP",
                signingId: VeloxControlConstants.hostBundleIdentifier,
                teamId: VeloxControlConstants.teamIdentifier,
                pid: 0,
                parentPid: 0,
                uid: 0,
                decisionLatencyMicros: UInt64(attempt.durationMillis) * 1_000,
                authResponseResult: "scheduled-at-rest-scan",
                resourcePath: attempt.scanId.lowercased(),
                pageURL: summary,
                interaction: attempt.trigger
            )
            eventLogger.logEventSync(event)
        }
        reply(#"{"ok":true}"#)
    }

    func syncEndpointDiscoveryClassifications(
        _ recordsJSON: String,
        withReply reply: @escaping (String) -> Void
    ) {
        guard let data = recordsJSON.data(using: .utf8), data.count <= 1_048_576,
              let records = try? JSONDecoder().decode([FileClassificationRecord].self, from: data),
              records.count <= 500 else {
            reply(errorJSON("Invalid classification-cache sync payload."))
            return
        }
        let policy = policyManager.policyEngine.currentPolicy()
        let configuredRules = Dictionary(
            uniqueKeysWithValues: policy.ocrControl.rules.map { ($0.ruleId, $0.classification) }
        )
        let valid = records.filter { record in
            record.filePath.hasPrefix("/") && record.filePath.count <= 4_096 &&
                record.fileSize >= 0 && record.modifiedAtSeconds >= 0 &&
                (0..<1_000_000_000).contains(record.modifiedAtNanoseconds) &&
                record.contentHashPrefix.count == 12 && record.contentHashPrefix.allSatisfy(\.isHexDigit) &&
                !record.ruleIds.isEmpty && record.ruleIds.count <= 100 &&
                record.ruleIds.count == record.classifications.count &&
                zip(record.ruleIds, record.classifications).allSatisfy { ruleId, classification in
                    configuredRules[ruleId] == classification
                }
        }
        guard valid.count == records.count else {
            reply(errorJSON("Classification-cache sync contained untrusted metadata."))
            return
        }
        classificationCache.upsert(valid)
        reply(#"{"ok":true,"acceptedCount":\#(valid.count)}"#)
    }

    func recordNetworkFlowEvent(_ payloadJSON: String, withReply reply: @escaping (String) -> Void) {
        guard let data = payloadJSON.data(using: .utf8), data.count <= 32_768,
              let received = try? JSONDecoder().decode(ExecutionEvent.self, from: data),
              received.module == "network-flow-control",
              received.action == "socket-connect",
              ["blocked", "would-block"].contains(received.decision) else {
            reply(errorJSON("Invalid network-flow event."))
            return
        }

        let destination = (received.resourcePath ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let executablePath = received.executablePath
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !destination.isEmpty,
              destination.count <= 2_048,
              !destination.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              !executablePath.isEmpty,
              executablePath.count <= 4_096,
              received.policyVersion >= 0,
              received.ruleId?.count ?? 0 <= 512,
              received.signingId?.count ?? 0 <= 512,
              received.teamId?.count ?? 0 <= 128 else {
            reply(errorJSON("Network-flow event contains invalid metadata."))
            return
        }

        let event = ExecutionEvent(
            module: "network-flow-control",
            action: "socket-connect",
            decision: received.decision,
            ruleId: received.ruleId,
            policyVersion: received.policyVersion,
            executablePath: executablePath,
            signingId: received.signingId,
            teamId: received.teamId,
            pid: received.pid,
            parentPid: received.parentPid,
            uid: received.uid,
            decisionLatencyMicros: received.decisionLatencyMicros,
            authResponseResult: received.authResponseResult,
            resourcePath: destination,
            pageURL: received.pageURL.map { String($0.prefix(32)) },
            interaction: received.interaction.map { String($0.prefix(64)) }
        )
        eventLogger.logEventSync(event)
        if event.decision == "blocked" {
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
            emailAttachmentControl: current.emailAttachmentControl,
            usbStorageControl: current.usbStorageControl,
            nearbyTransferControl: current.nearbyTransferControl,
            clipboardControl: current.clipboardControl,
            printerControl: current.printerControl,
            ocrControl: current.ocrControl,
            endpointDiscoveryControl: current.endpointDiscoveryControl,
            networkFlowControl: current.networkFlowControl,
            cloudSyncControl: current.cloudSyncControl,
            opticalDiskImageControl: current.opticalDiskImageControl,
            screenWatermarking: current.screenWatermarking,
            printToPDFControl: current.printToPDFControl
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
            // Container creation/attachment can take longer than the local web
            // bridge timeout. Reconcile asynchronously; the dashboard polls the
            // runtime snapshot and surfaces any provisioning error.
            usbEncryptionCoordinator.reconcileSoon()
            printerCoordinator.reconcileNow()
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
        let usbEncryption = usbEncryptionCoordinator.snapshot()
        let printer = printerCoordinator.snapshot()
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
                emailAttachmentMode: policy.emailAttachmentControl.mode.rawValue,
                emailClientCount: policy.emailAttachmentControl.mailClients.count,
                emailClientSigningIds: policy.emailAttachmentControl.mailClients.compactMap(\.signingId),
                emailProtectedClassifications: policy.emailAttachmentControl.protectedClassifications,
                emailCachedClassificationCount: classificationCache.count,
                usbStorageMode: policy.usbStorageControl.mode.rawValue,
                usbEncryptionMode: policy.usbStorageControl.encryptionMode.rawValue,
                usbContainerSizePercent: policy.usbStorageControl.containerSizePercent,
                usbExternalVolumeCount: usbEncryption.discoveredVolumeCount,
                usbEncryptedContainerCount: usbEncryption.encryptedContainerCount,
                usbEncryptionLastError: usbEncryption.lastError,
                nearbyTransferMode: policy.nearbyTransferControl.mode.rawValue,
                nearbyTransferProtectedDirectories: policy.nearbyTransferControl.protectedDirectoryNames,
                nearbyTransferBlocksAirDrop: policy.nearbyTransferControl.blockAirDrop,
                nearbyTransferBlocksBluetooth: policy.nearbyTransferControl.blockBluetoothFileTransfer,
                clipboardMode: policy.clipboardControl.mode.rawValue,
                clipboardBlockedRuleCount: policy.clipboardControl.blockedApplications.count,
                clipboardBlockedSigningIds: policy.clipboardControl.blockedApplications
                    .compactMap(\.signingId)
                    .map { $0.lowercased() },
                clipboardBlockedExecutablePaths: policy.clipboardControl.blockedApplications
                    .compactMap(\.executablePath),
                printerMode: policy.printerControl.mode.rawValue,
                printerQueueCount: printer.discoveredQueueCount,
                printerControlledQueueCount: printer.controlledQueueCount,
                printerLastError: printer.lastError,
                ocrMode: policy.ocrControl.mode.rawValue,
                screenshotOCRMode: policy.ocrControl.screenshotMode.rawValue,
                screenshotOCRRemediation: policy.ocrControl.screenshotRemediation.rawValue,
                ocrRuleCount: policy.ocrControl.rules.count,
                ocrRecognitionLanguages: policy.ocrControl.recognitionLanguages,
                ocrClassifications: policy.ocrControl.rules.map(\.classification),
                endpointDiscoveryMode: policy.endpointDiscoveryControl.mode.rawValue,
                endpointDiscoveryScheduleIntervalMinutes: policy.endpointDiscoveryControl.scheduleIntervalMinutes,
                endpointDiscoveryIncludesLocalHome: policy.endpointDiscoveryControl.includeLocalHome,
                endpointDiscoveryIncludesMountedVolumes: policy.endpointDiscoveryControl.includeMountedVolumes,
                endpointDiscoveryIncludesMountedShares: policy.endpointDiscoveryControl.includeMountedShares,
                endpointDiscoveryTagsClassifiedFiles: policy.endpointDiscoveryControl.tagClassifiedFiles,
                endpointDiscoveryMaxFilesPerScan: policy.endpointDiscoveryControl.maxFilesPerScan,
                networkFlowMode: policy.networkFlowControl.mode.rawValue,
                cloudSyncMode: policy.cloudSyncControl.mode.rawValue,
                opticalDiskImageMode: policy.opticalDiskImageControl.mode.rawValue,
                opticalDiskImageBlocksDiskImages: policy.opticalDiskImageControl.blockDiskImages,
                opticalDiskImageBlocksOpticalMedia: policy.opticalDiskImageControl.blockOpticalMedia,
                screenWatermarkingMode: policy.screenWatermarking.mode.rawValue,
                printToPDFMode: policy.printToPDFControl.mode.rawValue,
                networkFlowDefaultAction: policy.networkFlowControl.defaultAction.rawValue,
                networkFlowRuleCount: policy.networkFlowControl.rules.count,
                networkFlowRules: policy.networkFlowControl.rules,
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
