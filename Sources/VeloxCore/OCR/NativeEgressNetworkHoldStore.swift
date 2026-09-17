import Darwin
import Foundation

/// Cross-extension state used to close the native-app file-picker gap.
///
/// Some sandboxed apps receive an attachment through an Apple document broker
/// before the app performs its own observable file open. Endpoint Security can
/// still deny that later open, but the app may already hold the bytes. A short,
/// metadata-only hold lets the Network Filter stop outbound data while the host
/// classifies the file. No file content or recognized text is stored here.
public enum NativeEgressNetworkHoldStatus: String, Codable, Sendable {
    case pendingClassification = "pending-classification"
    case blockedContent = "blocked-content"
}

public struct NativeEgressNetworkHold: Codable, Sendable, Equatable {
    public let holdId: String
    public let filePath: String
    public let originSigningId: String
    public let teamId: String
    public let originPID: Int32
    public let status: NativeEgressNetworkHoldStatus
    public let policyVersion: Int
    public let classifications: [String]
    public let createdAtMillis: Int64
    public let expiresAtMillis: Int64

    public init(
        holdId: String = UUID().uuidString,
        filePath: String,
        originSigningId: String,
        teamId: String,
        originPID: Int32,
        status: NativeEgressNetworkHoldStatus,
        policyVersion: Int,
        classifications: [String],
        createdAtMillis: Int64,
        expiresAtMillis: Int64
    ) {
        self.holdId = holdId
        self.filePath = filePath
        self.originSigningId = originSigningId
        self.teamId = teamId
        self.originPID = originPID
        self.status = status
        self.policyVersion = policyVersion
        self.classifications = classifications
        self.createdAtMillis = createdAtMillis
        self.expiresAtMillis = expiresAtMillis
    }
}

private struct NativeEgressNetworkHoldDocument: Codable {
    let schemaVersion: Int
    var holds: [NativeEgressNetworkHold]
}

/// Thread-safe, bounded persistence shared by the Endpoint Security and Network
/// Filter system extensions. Reads fail open if the root-owned state is absent,
/// malformed, insecure, or expired.
public final class NativeEgressNetworkHoldStore: @unchecked Sendable {
    public static let defaultPath = "/Library/Application Support/VeloxMacDLP/native-egress-network-holds.json"
    public static let pendingLifetimeMillis: Int64 = 120_000
    public static let blockedLifetimeMillis: Int64 = 900_000
    /// Once the exact signed native client has been terminated after a
    /// protected verdict, keep a very short tail so its closing sockets cannot
    /// race the process shutdown. The long fail-closed lifetime remains in
    /// place if remediation cannot be verified.
    public static let remediatedLifetimeMillis: Int64 = 5_000

    private let path: String
    private let lock = NSLock()
    private let writerQueue = DispatchQueue(
        label: "co.velox.macdlp.native-egress-network-holds",
        qos: .userInitiated
    )
    private var cachedHolds: [NativeEgressNetworkHold] = []
    private var cachedFingerprint: FileFingerprint?

    private struct FileFingerprint: Equatable {
        let size: Int64
        let modifiedSeconds: Int64
        let modifiedNanoseconds: Int64
    }

    public init(path: String = NativeEgressNetworkHoldStore.defaultPath) {
        self.path = path
    }

    /// Queues persistence after the Endpoint Security authorization response.
    /// OCR never runs here and the kernel callback never waits on disk I/O.
    public func beginHoldAsync(
        filePath: String,
        process: ProcessContext,
        policyVersion: Int,
        classifications: [String],
        completion: (@Sendable (NativeEgressNetworkHold) -> Void)? = nil
    ) {
        let normalized = (filePath as NSString).standardizingPath
        let signingId = process.signingId?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let teamId = process.teamId?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard normalized.hasPrefix("/"), !signingId.isEmpty, !teamId.isEmpty else { return }

        writerQueue.async { [weak self] in
            guard let hold = self?.beginHold(
                filePath: normalized,
                signingId: signingId,
                teamId: teamId,
                originPID: process.pid,
                policyVersion: policyVersion,
                classifications: classifications
            ) else { return }
            completion?(hold)
        }
    }

    /// Resolves all pending holds for this immutable file identity. A clean
    /// verdict releases the network immediately; a protected verdict keeps the
    /// native client offline long enough to invalidate its staged transfer.
    @discardableResult
    public func resolveClassification(
        filePath: String,
        classifications: [String],
        policyVersion: Int
    ) -> [NativeEgressNetworkHold] {
        let normalized = (filePath as NSString).standardizingPath
        guard normalized.hasPrefix("/") else { return [] }

        lock.lock()
        defer { lock.unlock() }
        reloadLocked()
        let now = Self.nowMillis()
        var changed = false
        var next: [NativeEgressNetworkHold] = []
        var resolved: [NativeEgressNetworkHold] = []
        next.reserveCapacity(cachedHolds.count)

        for hold in cachedHolds where hold.expiresAtMillis > now {
            guard hold.filePath == normalized else {
                next.append(hold)
                continue
            }
            changed = true
            if !classifications.isEmpty {
                let protectedHold = NativeEgressNetworkHold(
                    holdId: hold.holdId,
                    filePath: hold.filePath,
                    originSigningId: hold.originSigningId,
                    teamId: hold.teamId,
                    originPID: hold.originPID,
                    status: .blockedContent,
                    policyVersion: policyVersion,
                    classifications: Array(classifications.prefix(32)),
                    createdAtMillis: hold.createdAtMillis,
                    expiresAtMillis: now + Self.blockedLifetimeMillis
                )
                next.append(protectedHold)
                resolved.append(protectedHold)
            } else {
                resolved.append(hold)
            }
        }

        if changed || next.count != cachedHolds.count {
            persistLocked(next)
        }
        return resolved
    }

    /// Shortens only the explicitly remediated holds. This is called after the
    /// exact signed process is gone (or has accepted SIGTERM), so a stale
    /// protected verdict cannot keep unrelated future files in that app offline.
    public func markRemediated(
        holdIds: Set<String>,
        nowMillis: Int64 = NativeEgressNetworkHoldStore.nowMillis()
    ) {
        guard !holdIds.isEmpty else { return }
        lock.lock()
        defer { lock.unlock() }
        reloadLocked()
        var changed = false
        let next = cachedHolds.compactMap { hold -> NativeEgressNetworkHold? in
            guard hold.expiresAtMillis > nowMillis else {
                changed = true
                return nil
            }
            guard holdIds.contains(hold.holdId), hold.status == .blockedContent else {
                return hold
            }
            changed = true
            return NativeEgressNetworkHold(
                holdId: hold.holdId,
                filePath: hold.filePath,
                originSigningId: hold.originSigningId,
                teamId: hold.teamId,
                originPID: hold.originPID,
                status: hold.status,
                policyVersion: hold.policyVersion,
                classifications: hold.classifications,
                createdAtMillis: hold.createdAtMillis,
                expiresAtMillis: min(
                    hold.expiresAtMillis,
                    nowMillis + Self.remediatedLifetimeMillis
                )
            )
        }
        if changed {
            persistLocked(next)
        }
    }

    /// Returns an active hold only for an exact configured native client. The
    /// caller already verifies the signing identity against policy; Team ID
    /// correlation lets a main app hold also cover its signed upload helper.
    public func activeHold(
        signingId: String?,
        teamId: String?,
        nowMillis: Int64 = NativeEgressNetworkHoldStore.nowMillis()
    ) -> NativeEgressNetworkHold? {
        let normalizedSigningId = signingId?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let normalizedTeamId = teamId?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !normalizedSigningId.isEmpty else { return nil }

        lock.lock()
        defer { lock.unlock() }
        reloadLocked()
        return cachedHolds
            .filter { hold in
                hold.expiresAtMillis > nowMillis &&
                    ((!normalizedTeamId.isEmpty && hold.teamId.caseInsensitiveCompare(normalizedTeamId) == .orderedSame) ||
                     hold.originSigningId.caseInsensitiveCompare(normalizedSigningId) == .orderedSame)
            }
            .sorted { lhs, rhs in lhs.createdAtMillis > rhs.createdAtMillis }
            .first
    }

    public func clear() {
        lock.lock()
        defer { lock.unlock() }
        persistLocked([])
    }

    private func beginHold(
        filePath: String,
        signingId: String,
        teamId: String,
        originPID: pid_t,
        policyVersion: Int,
        classifications: [String]
    ) -> NativeEgressNetworkHold {
        lock.lock()
        defer { lock.unlock() }
        reloadLocked()
        let now = Self.nowMillis()
        let status: NativeEgressNetworkHoldStatus = classifications.isEmpty
            ? .pendingClassification
            : .blockedContent
        let lifetime = classifications.isEmpty
            ? Self.pendingLifetimeMillis
            : Self.blockedLifetimeMillis
        var next = cachedHolds.filter {
            $0.expiresAtMillis > now && !(
                $0.filePath == filePath &&
                $0.teamId.caseInsensitiveCompare(teamId) == .orderedSame
            )
        }
        let hold = NativeEgressNetworkHold(
            filePath: filePath,
            originSigningId: signingId,
            teamId: teamId,
            originPID: Int32(originPID),
            status: status,
            policyVersion: policyVersion,
            classifications: Array(classifications.prefix(32)),
            createdAtMillis: now,
            expiresAtMillis: now + lifetime
        )
        next.append(hold)
        if next.count > 256 {
            next = Array(next.sorted { $0.createdAtMillis > $1.createdAtMillis }.prefix(256))
        }
        persistLocked(next)
        return hold
    }

    private func reloadLocked() {
        var info = stat()
        guard lstat(path, &info) == 0,
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              info.st_mode & mode_t(S_IWGRP | S_IWOTH) == 0,
              info.st_size >= 0,
              info.st_size <= 1_048_576 else {
            cachedHolds = []
            cachedFingerprint = nil
            return
        }
        let fingerprint = FileFingerprint(
            size: Int64(info.st_size),
            modifiedSeconds: Int64(info.st_mtimespec.tv_sec),
            modifiedNanoseconds: Int64(info.st_mtimespec.tv_nsec)
        )
        guard fingerprint != cachedFingerprint else { return }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: [.mappedIfSafe]),
              let document = try? JSONDecoder().decode(NativeEgressNetworkHoldDocument.self, from: data),
              document.schemaVersion == 1,
              document.holds.count <= 256,
              document.holds.allSatisfy(Self.isValid) else {
            cachedHolds = []
            cachedFingerprint = fingerprint
            return
        }
        cachedHolds = document.holds
        cachedFingerprint = fingerprint
    }

    private func persistLocked(_ holds: [NativeEgressNetworkHold]) {
        let document = NativeEgressNetworkHoldDocument(schemaVersion: 1, holds: holds)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(document) else { return }
        let destination = URL(fileURLWithPath: path)
        let parent = destination.deletingLastPathComponent()
        do {
            try FileManager.default.createDirectory(
                at: parent,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o755]
            )
            try data.write(to: destination, options: .atomic)
            _ = chmod(path, mode_t(S_IRUSR | S_IWUSR))
            if geteuid() == 0 { _ = chown(path, 0, 0) }
            cachedHolds = holds
            var info = stat()
            if lstat(path, &info) == 0 {
                cachedFingerprint = FileFingerprint(
                    size: Int64(info.st_size),
                    modifiedSeconds: Int64(info.st_mtimespec.tv_sec),
                    modifiedNanoseconds: Int64(info.st_mtimespec.tv_nsec)
                )
            } else {
                cachedFingerprint = nil
            }
        } catch {
            // The network backstop is additive. Endpoint Security's original
            // deny remains authoritative if this bounded state cannot persist.
        }
    }

    private static func isValid(_ hold: NativeEgressNetworkHold) -> Bool {
        UUID(uuidString: hold.holdId) != nil &&
            hold.filePath.hasPrefix("/") && hold.filePath.count <= 4_096 &&
            !hold.originSigningId.isEmpty && hold.originSigningId.count <= 512 &&
            !hold.teamId.isEmpty && hold.teamId.count <= 128 &&
            hold.policyVersion >= 0 &&
            hold.classifications.count <= 32 &&
            hold.classifications.allSatisfy { !$0.isEmpty && $0.count <= 256 } &&
            hold.createdAtMillis > 0 &&
            hold.expiresAtMillis > hold.createdAtMillis &&
            hold.expiresAtMillis - hold.createdAtMillis <= blockedLifetimeMillis
    }

    public static func nowMillis() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1_000)
    }
}
