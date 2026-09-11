import Darwin
import Foundation

public struct ManagedUSBEncryptionVolume: Sendable, Equatable {
    public let identifier: String
    public let volumeName: String
    public let mountPath: String
    public let containerBackingPath: String

    public init(
        identifier: String,
        volumeName: String,
        mountPath: String,
        containerBackingPath: String
    ) {
        self.identifier = identifier
        self.volumeName = volumeName
        self.mountPath = mountPath
        self.containerBackingPath = containerBackingPath
    }
}

public enum USBEncryptionMutationOperation: String, Sendable {
    case open = "plaintext-write-open"
    case create = "plaintext-create"
    case copyFile = "plaintext-copyfile"
}

public struct USBEncryptionWriteDecision: Sendable, Equatable {
    public let isCandidate: Bool
    public let shouldAllow: Bool
    public let decisionString: String
    public let matchingRuleId: String?
    public let policyVersion: Int
    public let volumeName: String?
    public let volumeMountPath: String?
    public let operation: USBEncryptionMutationOperation

    public init(
        isCandidate: Bool,
        shouldAllow: Bool,
        decisionString: String,
        matchingRuleId: String?,
        policyVersion: Int,
        volumeName: String?,
        volumeMountPath: String?,
        operation: USBEncryptionMutationOperation
    ) {
        self.isCandidate = isCandidate
        self.shouldAllow = shouldAllow
        self.decisionString = decisionString
        self.matchingRuleId = matchingRuleId
        self.policyVersion = policyVersion
        self.volumeName = volumeName
        self.volumeMountPath = volumeMountPath
        self.operation = operation
    }
}

/// Thread-safe, in-memory authorization state for encrypted removable media.
///
/// Endpoint Security cannot redirect a Finder copy. In enforce mode this
/// controller therefore denies mutations to each physical outer volume while
/// allowing only Apple's disk-image stack and the authenticated Velox ES client
/// to update the encrypted sparse-bundle backing store. Files written to the
/// separately mounted encrypted volume are not under the outer mount path and
/// remain allowed.
public final class USBEncryptionAccessController: @unchecked Sendable {
    private struct State {
        var mode: PolicyMode = .disabled
        var policyVersion: Int = 1
        var volumes: [ManagedUSBEncryptionVolume] = []
    }

    private let lock = NSLock()
    private var state = State()

    public init() {}

    public func update(
        mode: PolicyMode,
        policyVersion: Int,
        volumes: [ManagedUSBEncryptionVolume]
    ) {
        lock.lock()
        state = State(
            mode: mode,
            policyVersion: policyVersion,
            volumes: volumes.sorted { $0.mountPath.count > $1.mountPath.count }
        )
        lock.unlock()
    }

    public func evaluateOpen(
        process: ProcessContext,
        filePath: String,
        requestedFlags: UInt32
    ) -> USBEncryptionWriteDecision? {
        let flags = Int32(bitPattern: requestedFlags)
        let accessMode = flags & O_ACCMODE
        let isWrite = accessMode == O_WRONLY ||
            accessMode == O_RDWR ||
            (flags & O_APPEND) != 0 ||
            (flags & O_TRUNC) != 0
        guard isWrite else { return nil }
        return evaluateMutation(
            process: process,
            destinationPath: filePath,
            operation: .open
        )
    }

    /// Returns the physical removable volume containing a destination. Volume
    /// discovery runs regardless of encrypted-container mode, allowing the
    /// shared content policy to protect ordinary USB copies as well.
    public func externalVolume(containing destinationPath: String) -> ManagedUSBEncryptionVolume? {
        lock.lock()
        let volumes = state.volumes
        lock.unlock()
        let standardizedPath = (destinationPath as NSString).standardizingPath
        return volumes.first(where: {
            Self.contains(path: standardizedPath, root: $0.mountPath)
        })
    }

    public func evaluateMutation(
        process: ProcessContext,
        destinationPath: String,
        operation: USBEncryptionMutationOperation
    ) -> USBEncryptionWriteDecision? {
        lock.lock()
        let snapshot = state
        lock.unlock()

        guard snapshot.mode != .disabled else { return nil }
        let standardizedPath = (destinationPath as NSString).standardizingPath
        guard let volume = snapshot.volumes.first(where: {
            Self.contains(path: standardizedPath, root: $0.mountPath)
        }) else {
            return nil
        }

        let containerDirectory = (volume.containerBackingPath as NSString).deletingLastPathComponent
        if Self.contains(path: standardizedPath, root: containerDirectory),
           Self.isTrustedContainerWriter(process) {
            return nil
        }

        let shouldAllow = snapshot.mode != .enforce
        return USBEncryptionWriteDecision(
            isCandidate: true,
            shouldAllow: shouldAllow,
            decisionString: shouldAllow ? "would-encrypt" : "blocked",
            matchingRuleId: shouldAllow
                ? "usb-encryption-plaintext-write-audit"
                : "usb-encryption-container-required",
            policyVersion: snapshot.policyVersion,
            volumeName: volume.volumeName,
            volumeMountPath: volume.mountPath,
            operation: operation
        )
    }

    private static func contains(path: String, root: String) -> Bool {
        let normalizedRoot = (root as NSString).standardizingPath
        return path == normalizedRoot || path.hasPrefix(normalizedRoot + "/")
    }

    private static func isTrustedContainerWriter(_ process: ProcessContext) -> Bool {
        if process.isESClient,
           process.signingId == VeloxControlConstants.hostBundleIdentifier + ".endpointsecurity",
           process.teamId == VeloxControlConstants.teamIdentifier {
            return true
        }

        guard process.isPlatformBinary else { return false }
        let trustedPaths = [
            "/usr/bin/hdiutil",
            "/usr/libexec/diskimagesiod",
            "/System/Library/PrivateFrameworks/DiskImages.framework/Versions/A/Resources/diskimages-helper"
        ]
        return trustedPaths.contains(process.executablePath)
    }
}
