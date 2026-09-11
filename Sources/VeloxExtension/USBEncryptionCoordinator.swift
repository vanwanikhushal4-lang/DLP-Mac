import Darwin
import Foundation
import Security
import VeloxCore
import os.log

struct USBEncryptionRuntimeSnapshot: Sendable {
    let discoveredVolumeCount: Int
    let encryptedContainerCount: Int
    let lastError: String?
}

private struct USBContainerKeyState: Codable, Sendable {
    var keysByContainerIdentifier: [String: String]
}

private struct USBCommandResult: Sendable {
    let terminationStatus: Int32
    let output: Data

    var succeeded: Bool { terminationStatus == 0 }
    var outputString: String { String(decoding: output, as: UTF8.self) }
}

/// Provisions one AES-256 APFS sparse bundle per physical removable volume.
///
/// The outer drive remains mounted only as the encrypted backing store. The
/// Endpoint Security authorization path blocks ordinary writes there, while
/// users write normally to the separately mounted `Velox Secure USB` volume.
/// Recovery keys are prototype-local, root-readable only, and never logged.
final class USBEncryptionCoordinator: @unchecked Sendable {
    static let defaultKeyStatePath =
        "/Library/Application Support/VeloxMacDLP/usb-container-keys.json"
    static let containerDirectoryName = ".velox"
    static let containerBundleName = "VeloxSecure.sparsebundle"
    static let containerIdentifierName = "container-id"

    private let policyEngine: PolicyEngine
    private let eventLogger: EventLogger
    private let accessController: USBEncryptionAccessController
    private let managedVirtualMountAllowance: ManagedVirtualMountAllowance
    private let keyStatePath: String
    private let workQueue = DispatchQueue(label: "co.velox.macdlp.usb-encryption", qos: .utility)
    private let snapshotLock = NSLock()
    private let logger = Logger(subsystem: "co.velox.macdlp.endpointsecurity", category: "USBEncryption")

    private var timer: DispatchSourceTimer?
    private var auditedMissingContainers = Set<String>()
    private var currentSnapshot = USBEncryptionRuntimeSnapshot(
        discoveredVolumeCount: 0,
        encryptedContainerCount: 0,
        lastError: nil
    )

    init(
        policyEngine: PolicyEngine,
        eventLogger: EventLogger,
        accessController: USBEncryptionAccessController,
        managedVirtualMountAllowance: ManagedVirtualMountAllowance,
        keyStatePath: String = USBEncryptionCoordinator.defaultKeyStatePath
    ) {
        self.policyEngine = policyEngine
        self.eventLogger = eventLogger
        self.accessController = accessController
        self.managedVirtualMountAllowance = managedVirtualMountAllowance
        self.keyStatePath = keyStatePath
    }

    func start() {
        workQueue.sync {
            guard timer == nil else { return }
            reconcile()

            let timer = DispatchSource.makeTimerSource(queue: workQueue)
            timer.schedule(deadline: .now() + 1, repeating: 2, leeway: .milliseconds(200))
            timer.setEventHandler { [weak self] in self?.reconcile() }
            self.timer = timer
            timer.resume()
        }
    }

    func stop() {
        workQueue.sync {
            timer?.cancel()
            timer = nil
            accessController.update(mode: .disabled, policyVersion: 1, volumes: [])
        }
    }

    func reconcileSoon() {
        workQueue.async { [weak self] in self?.reconcile() }
    }

    func reconcileNow() {
        workQueue.sync { reconcile() }
    }

    func snapshot() -> USBEncryptionRuntimeSnapshot {
        snapshotLock.lock()
        defer { snapshotLock.unlock() }
        return currentSnapshot
    }

    private func reconcile() {
        let policy = policyEngine.currentPolicy()
        let config = policy.usbStorageControl

        do {
            let volumes = try discoverExternalVolumes()
            let managedVolumes = volumes.map { volume in
                ManagedUSBEncryptionVolume(
                    identifier: volume.deviceIdentifier,
                    volumeName: volume.volumeName,
                    mountPath: volume.mountPath,
                    containerBackingPath: containerPath(for: volume)
                )
            }

            // Publish the outer-volume deny boundary before provisioning so
            // no user copy can race the creation of the encrypted container.
            accessController.update(
                mode: config.encryptionMode,
                policyVersion: policy.policyVersion,
                volumes: managedVolumes
            )

            var readyCount = 0
            var reconciliationErrors: [String] = []
            switch config.encryptionMode {
            case .enforce:
                auditedMissingContainers.removeAll()
                for volume in volumes {
                    do {
                        if try ensureContainerReady(
                            for: volume,
                            sizePercent: config.containerSizePercent,
                            policyVersion: policy.policyVersion
                        ) {
                            readyCount += 1
                        }
                    } catch {
                        reconciliationErrors.append("\(volume.volumeName): \(error)")
                    }
                }
            case .auditOnly:
                for volume in volumes {
                    if FileManager.default.fileExists(atPath: containerPath(for: volume)) {
                        readyCount += 1
                    } else if auditedMissingContainers.insert(volume.deviceIdentifier).inserted {
                        eventLogger.logEventAsync(
                            containerEvent(
                                action: "container-required",
                                decision: "would-encrypt",
                                policyVersion: policy.policyVersion,
                                volume: volume,
                                result: "audit-only"
                            )
                        )
                    }
                }
                let connected = Set(volumes.map(\.deviceIdentifier))
                auditedMissingContainers.formIntersection(connected)
            case .disabled:
                auditedMissingContainers.removeAll()
                readyCount = volumes.filter {
                    FileManager.default.fileExists(atPath: containerPath(for: $0))
                }.count
            }

            let errorMessage = reconciliationErrors.isEmpty
                ? nil
                : reconciliationErrors.joined(separator: "; ")
            if let errorMessage {
                logger.error("USB encryption reconciliation failed: \(errorMessage, privacy: .public)")
            }
            publishSnapshot(
                discoveredVolumeCount: volumes.count,
                encryptedContainerCount: readyCount,
                lastError: errorMessage
            )
        } catch {
            let message = String(describing: error)
            logger.error("Unable to discover removable volumes: \(message, privacy: .public)")
            accessController.update(
                mode: config.encryptionMode,
                policyVersion: policy.policyVersion,
                volumes: []
            )
            publishSnapshot(
                discoveredVolumeCount: 0,
                encryptedContainerCount: 0,
                lastError: message
            )
        }
    }

    private func discoverExternalVolumes() throws -> [ExternalUSBVolumeDescriptor] {
        let result = try run(
            "/usr/sbin/diskutil",
            arguments: ["list", "-plist", "external", "physical"]
        )
        guard result.succeeded else {
            throw USBEncryptionError.commandFailed("diskutil list", result.outputString)
        }
        return try ExternalUSBVolumeParser.parseDiskutilListPlist(result.output)
    }

    private func ensureContainerReady(
        for volume: ExternalUSBVolumeDescriptor,
        sizePercent: Int,
        policyVersion: Int
    ) throws -> Bool {
        let fileManager = FileManager.default
        let directoryPath = containerDirectoryPath(for: volume)
        let bundlePath = containerPath(for: volume)
        let identifierPath = (directoryPath as NSString)
            .appendingPathComponent(Self.containerIdentifierName)

        try fileManager.createDirectory(
            atPath: directoryPath,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        _ = chmod(directoryPath, 0o700)

        let bundleExists = fileManager.fileExists(atPath: bundlePath)
        let containerIdentifier = try loadOrCreateContainerIdentifier(
            at: identifierPath,
            bundleAlreadyExists: bundleExists
        )
        let passphrase = try loadOrCreatePassphrase(
            for: containerIdentifier,
            allowCreation: !bundleExists
        )

        if !bundleExists {
            let sizeMB = max(256, Int(volume.sizeBytes / 1_048_576) * sizePercent / 100)
            let create = try run(
                "/usr/bin/hdiutil",
                arguments: [
                    "create",
                    "-type", "SPARSEBUNDLE",
                    "-fs", "APFS",
                    "-volname", "Velox Secure USB",
                    "-size", "\(sizeMB)m",
                    "-encryption", "AES-256",
                    "-stdinpass",
                    bundlePath
                ],
                standardInput: passphrase + "\n"
            )
            guard create.succeeded else {
                throw USBEncryptionError.commandFailed("hdiutil create", create.outputString)
            }
            eventLogger.logEventAsync(
                containerEvent(
                    action: "container-created",
                    decision: "encrypted",
                    policyVersion: policyVersion,
                    volume: volume,
                    result: "aes-256-apfs-sparsebundle"
                )
            )
        }

        if try attachedMountPoint(forImagePath: bundlePath) != nil {
            return true
        }

        let mountAllowance = managedVirtualMountAllowance.begin(
            baseVolumeName: "Velox Secure USB"
        )
        defer { managedVirtualMountAllowance.end(mountAllowance) }
        let attach = try run(
            "/usr/bin/hdiutil",
            arguments: ["attach", "-plist", "-stdinpass", bundlePath],
            standardInput: passphrase + "\n"
        )
        guard attach.succeeded,
              Self.mountPoint(fromAttachPlist: attach.output) != nil else {
            throw USBEncryptionError.commandFailed("hdiutil attach", attach.outputString)
        }

        eventLogger.logEventAsync(
            containerEvent(
                action: "container-mounted",
                decision: "encrypted",
                policyVersion: policyVersion,
                volume: volume,
                result: "ready-for-secure-copy"
            )
        )
        return true
    }

    private func loadOrCreateContainerIdentifier(
        at path: String,
        bundleAlreadyExists: Bool
    ) throws -> String {
        if let value = try? String(contentsOfFile: path, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines),
           UUID(uuidString: value) != nil {
            return value
        }

        guard !bundleAlreadyExists else {
            throw USBEncryptionError.missingContainerIdentity
        }

        let identifier = UUID().uuidString
        try Data((identifier + "\n").utf8).write(
            to: URL(fileURLWithPath: path),
            options: .atomic
        )
        _ = chmod(path, 0o600)
        return identifier
    }

    private func loadOrCreatePassphrase(
        for containerIdentifier: String,
        allowCreation: Bool
    ) throws -> String {
        var state = try loadKeyState()
        if let existing = state.keysByContainerIdentifier[containerIdentifier] {
            return existing
        }

        guard allowCreation else { throw USBEncryptionError.recoveryKeyUnavailable }
        var bytes = [UInt8](repeating: 0, count: 32)
        let randomStatus = bytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
        }
        guard randomStatus == errSecSuccess else {
            throw USBEncryptionError.randomGenerationFailed
        }
        let passphrase = Data(bytes).base64EncodedString()
        state.keysByContainerIdentifier[containerIdentifier] = passphrase
        try persistKeyState(state)
        return passphrase
    }

    private func loadKeyState() throws -> USBContainerKeyState {
        guard FileManager.default.fileExists(atPath: keyStatePath) else {
            return USBContainerKeyState(keysByContainerIdentifier: [:])
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: keyStatePath))
        return try JSONDecoder().decode(USBContainerKeyState.self, from: data)
    }

    private func persistKeyState(_ state: USBContainerKeyState) throws {
        let directory = (keyStatePath as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(
            atPath: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755]
        )
        let data = try JSONEncoder().encode(state)
        try data.write(to: URL(fileURLWithPath: keyStatePath), options: .atomic)
        _ = chmod(keyStatePath, 0o600)
    }

    private func attachedMountPoint(forImagePath imagePath: String) throws -> String? {
        let result = try run("/usr/bin/hdiutil", arguments: ["info", "-plist"])
        guard result.succeeded else {
            throw USBEncryptionError.commandFailed("hdiutil info", result.outputString)
        }
        return Self.mountPoint(forImagePath: imagePath, fromInfoPlist: result.output)
    }

    private static func mountPoint(fromAttachPlist data: Data) -> String? {
        guard let plist = try? PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: nil
        ) as? [String: Any] else {
            return nil
        }
        return mountPoint(fromSystemEntities: plist["system-entities"])
    }

    private static func mountPoint(forImagePath imagePath: String, fromInfoPlist data: Data) -> String? {
        guard let plist = try? PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: nil
        ) as? [String: Any],
              let images = plist["images"] as? [[String: Any]] else {
            return nil
        }
        let standardizedImagePath = (imagePath as NSString).standardizingPath
        guard let image = images.first(where: {
            guard let value = $0["image-path"] as? String else { return false }
            return (value as NSString).standardizingPath == standardizedImagePath
        }) else {
            return nil
        }
        return mountPoint(fromSystemEntities: image["system-entities"])
    }

    private static func mountPoint(fromSystemEntities value: Any?) -> String? {
        guard let entities = value as? [[String: Any]] else { return nil }
        return entities.compactMap { $0["mount-point"] as? String }.first
    }

    private func run(
        _ executable: String,
        arguments: [String],
        standardInput: String? = nil
    ) throws -> USBCommandResult {
        let process = Process()
        let outputPipe = Pipe()
        let inputPipe = standardInput == nil ? nil : Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = outputPipe
        process.standardError = outputPipe
        process.standardInput = inputPipe
        var environment = ProcessInfo.processInfo.environment
        environment["LC_ALL"] = "C"
        environment["LANG"] = "C"
        process.environment = environment

        try process.run()
        if let standardInput, let inputPipe {
            inputPipe.fileHandleForWriting.write(Data(standardInput.utf8))
            try? inputPipe.fileHandleForWriting.close()
        }
        process.waitUntilExit()
        return USBCommandResult(
            terminationStatus: process.terminationStatus,
            output: outputPipe.fileHandleForReading.readDataToEndOfFile()
        )
    }

    private func containerDirectoryPath(for volume: ExternalUSBVolumeDescriptor) -> String {
        (volume.mountPath as NSString).appendingPathComponent(Self.containerDirectoryName)
    }

    private func containerPath(for volume: ExternalUSBVolumeDescriptor) -> String {
        (containerDirectoryPath(for: volume) as NSString)
            .appendingPathComponent(Self.containerBundleName)
    }

    private func containerEvent(
        action: String,
        decision: String,
        policyVersion: Int,
        volume: ExternalUSBVolumeDescriptor,
        result: String
    ) -> ExecutionEvent {
        ExecutionEvent(
            module: "usb-encryption-control",
            action: action,
            decision: decision,
            ruleId: "usb-encryption-container",
            policyVersion: policyVersion,
            executablePath: "/usr/bin/hdiutil",
            signingId: "com.apple.hdiutil",
            teamId: nil,
            pid: 0,
            parentPid: 0,
            uid: 0,
            decisionLatencyMicros: 1,
            authResponseResult: result,
            resourcePath: volume.mountPath,
            interaction: "encrypted-container"
        )
    }

    private func publishSnapshot(
        discoveredVolumeCount: Int,
        encryptedContainerCount: Int,
        lastError: String?
    ) {
        snapshotLock.lock()
        currentSnapshot = USBEncryptionRuntimeSnapshot(
            discoveredVolumeCount: discoveredVolumeCount,
            encryptedContainerCount: encryptedContainerCount,
            lastError: lastError
        )
        snapshotLock.unlock()
    }
}

private enum USBEncryptionError: Error, CustomStringConvertible {
    case commandFailed(String, String)
    case missingContainerIdentity
    case recoveryKeyUnavailable
    case randomGenerationFailed

    var description: String {
        switch self {
        case .commandFailed(let command, let output):
            let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? "\(command) failed" : "\(command) failed: \(trimmed)"
        case .missingContainerIdentity:
            return "encrypted container exists but its Velox identity is missing"
        case .recoveryKeyUnavailable:
            return "encrypted container recovery key is unavailable on this Mac"
        case .randomGenerationFailed:
            return "unable to generate a cryptographic recovery key"
        }
    }
}
