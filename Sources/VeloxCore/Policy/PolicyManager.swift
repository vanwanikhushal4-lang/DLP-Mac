import Foundation
import os

public final class PolicyManager: @unchecked Sendable {
    public static let defaultPolicyPath = "/Library/Application Support/VeloxMacDLP/policy.json"

    public let policyPath: String
    public let policyEngine: PolicyEngine
    private let logger: EventLogger?

    private var fileSource: DispatchSourceFileSystemObject?
    private var fileDescriptor: Int32 = -1
    private let monitorQueue = DispatchQueue(label: "co.velox.macdlp.policy.monitor", qos: .utility)

    public var onPolicyReloaded: (@Sendable (VeloxPolicy) -> Void)?
    public var onPolicyError: (@Sendable (String) -> Void)?

    public init(
        policyPath: String = PolicyManager.defaultPolicyPath,
        initialPolicy: VeloxPolicy? = nil,
        logger: EventLogger? = nil
    ) {
        self.policyPath = policyPath
        self.logger = logger

        let startingPolicy: VeloxPolicy
        if let initial = initialPolicy {
            startingPolicy = initial
        } else if let loaded = PolicyManager.loadPolicyFromFile(at: policyPath) {
            startingPolicy = loaded
        } else {
            // Default fallback policy: version 1, enforce mode, allow-all
            startingPolicy = VeloxPolicy(
                policyVersion: 1,
                applicationControl: ApplicationControlConfig(mode: .enforce, blockedApplications: [], allowedApplications: [])
            )
        }

        self.policyEngine = PolicyEngine(policy: startingPolicy)
    }

    deinit {
        stopMonitoring()
    }

    public static func loadPolicyFromFile(at path: String) -> VeloxPolicy? {
        guard FileManager.default.fileExists(atPath: path) else {
            return nil
        }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return nil
        }
        do {
            return try VeloxPolicy.decodeStrict(from: data)
        } catch {
            return nil
        }
    }

    /// Attempts to reload the policy from disk.
    /// If the file is missing or invalid JSON/schema/unknown properties/rollback,
    /// preserves the last valid policy in memory, emits an error event into the structured log,
    /// and triggers error reporting.
    @discardableResult
    public func reloadPolicyFromDisk() -> Bool {
        guard FileManager.default.fileExists(atPath: policyPath) else {
            let msg = "Policy file at '\(policyPath)' does not exist. Retaining current active policy."
            reportError(msg)
            return false
        }

        let data: Data
        do {
            data = try Data(contentsOf: URL(fileURLWithPath: policyPath))
        } catch {
            let msg = "Failed to read policy file at '\(policyPath)': \(error.localizedDescription)."
            reportError(msg)
            return false
        }

        let newPolicy: VeloxPolicy
        do {
            newPolicy = try VeloxPolicy.decodeStrict(from: data)
        } catch {
            let msg = "Policy file at '\(policyPath)' rejected: \(error)."
            reportError(msg)
            return false
        }

        let currentVersion = policyEngine.currentPolicy().policyVersion
        if newPolicy.policyVersion < currentVersion {
            let msg = "Policy rollback rejected: version \(newPolicy.policyVersion) is lower than active version \(currentVersion)."
            reportError(msg)
            return false
        }

        policyEngine.updatePolicy(newPolicy)
        onPolicyReloaded?(newPolicy)
        return true
    }

    private func reportError(_ message: String) {
        let currentVersion = policyEngine.currentPolicy().policyVersion
        fputs("[VeloxPolicyManager] \(message) Retaining last valid policy (version \(currentVersion)).\n", stderr)

        // Emit policy error to structured JSONL log
        let errorEvent = ExecutionEvent(
            timestamp: nil,
            eventId: UUID().uuidString,
            module: "policy-manager",
            action: "policy-error",
            decision: "retained-last-valid",
            ruleId: nil,
            policyVersion: currentVersion,
            executablePath: policyPath,
            signingId: nil,
            teamId: nil,
            pid: getpid(),
            parentPid: getppid(),
            uid: getuid(),
            decisionLatencyMicros: 0
        )
        logger?.logEventAsync(errorEvent)

        onPolicyError?(message)
    }

    public func startMonitoring() {
        stopMonitoring()

        let parentDir = (policyPath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: parentDir, withIntermediateDirectories: true)

        let fd = open(policyPath, O_EVTONLY)
        if fd < 0 {
            let dirFd = open(parentDir, O_EVTONLY)
            if dirFd >= 0 {
                self.fileDescriptor = dirFd
                let source = DispatchSource.makeFileSystemObjectSource(
                    fileDescriptor: dirFd,
                    eventMask: [.write, .extend, .rename, .attrib],
                    queue: monitorQueue
                )
                source.setEventHandler { [weak self] in
                    self?.handleFileOrDirChange()
                }
                source.setCancelHandler {
                    close(dirFd)
                }
                source.resume()
                self.fileSource = source
            }
            return
        }

        self.fileDescriptor = fd
        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.delete, .write, .extend, .attrib, .rename],
            queue: monitorQueue
        )

        source.setEventHandler { [weak self] in
            guard let self = self else { return }
            let flags = source.data
            if flags.contains(.delete) || flags.contains(.rename) {
                self.handleFileOrDirChange()
                self.startMonitoring()
            } else if flags.contains(.write) || flags.contains(.extend) || flags.contains(.attrib) {
                self.handleFileOrDirChange()
            }
        }

        source.setCancelHandler {
            close(fd)
        }

        source.resume()
        self.fileSource = source
    }

    public func stopMonitoring() {
        if let source = fileSource {
            source.cancel()
            self.fileSource = nil
            self.fileDescriptor = -1
        }
    }

    private func handleFileOrDirChange() {
        monitorQueue.asyncAfter(deadline: .now() + .milliseconds(100)) { [weak self] in
            self?.reloadPolicyFromDisk()
        }
    }
}
