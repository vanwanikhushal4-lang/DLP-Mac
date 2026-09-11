import Foundation
import os

/// A narrow, short-lived exemption used only while Velox attaches its own
/// encrypted USB container. Without it, Disk Image Control would correctly see
/// the APFS sparse bundle as a virtual file-backed mount and deny it.
public final class ManagedVirtualMountAllowance: @unchecked Sendable {
    public struct Token: Hashable, Sendable {
        fileprivate let identifier: UUID
    }

    private struct Entry {
        let baseVolumeName: String
        let expiresAtUptimeNanoseconds: UInt64
    }

    private let lock = os_unfair_lock_t.allocate(capacity: 1)
    private var entries: [UUID: Entry] = [:]

    public init() {
        lock.initialize(to: os_unfair_lock())
    }

    deinit { lock.deallocate() }

    public func begin(
        baseVolumeName: String,
        lifetimeSeconds: UInt64 = 120
    ) -> Token {
        let token = Token(identifier: UUID())
        let now = DispatchTime.now().uptimeNanoseconds
        let lifetime = min(max(lifetimeSeconds, 1), 300) * 1_000_000_000

        os_unfair_lock_lock(lock)
        removeExpiredEntries(now: now)
        entries[token.identifier] = Entry(
            baseVolumeName: baseVolumeName,
            expiresAtUptimeNanoseconds: now &+ lifetime
        )
        os_unfair_lock_unlock(lock)
        return token
    }

    public func end(_ token: Token) {
        os_unfair_lock_lock(lock)
        entries.removeValue(forKey: token.identifier)
        os_unfair_lock_unlock(lock)
    }

    /// Allows only an authentic Apple disk-image stack mounting the expected
    /// Velox volume name while a coordinator-issued token is still active.
    public func allows(process: ProcessContext, mountPoint: String) -> Bool {
        guard process.isPlatformBinary,
              Self.isTrustedAppleMountProcess(process) else { return false }

        let volumeName = (mountPoint as NSString).lastPathComponent
        guard !volumeName.isEmpty else { return false }

        let now = DispatchTime.now().uptimeNanoseconds
        os_unfair_lock_lock(lock)
        removeExpiredEntries(now: now)
        let allowed = entries.values.contains {
            Self.matchesVolumeName(volumeName, baseName: $0.baseVolumeName)
        }
        os_unfair_lock_unlock(lock)
        return allowed
    }

    private func removeExpiredEntries(now: UInt64) {
        entries = entries.filter { $0.value.expiresAtUptimeNanoseconds >= now }
    }

    private static func matchesVolumeName(_ volumeName: String, baseName: String) -> Bool {
        if volumeName == baseName { return true }
        let prefix = baseName + " "
        guard volumeName.hasPrefix(prefix) else { return false }
        return volumeName.dropFirst(prefix.count).allSatisfy(\.isNumber)
    }

    private static func isTrustedAppleMountProcess(_ process: ProcessContext) -> Bool {
        let signingId = process.signingId?.lowercased() ?? ""
        let executablePath = process.executablePath.lowercased()
        let signingIds: Set<String> = [
            "com.apple.hdiutil",
            "com.apple.diskimagemounter",
            "com.apple.diskimages-helper",
            "com.apple.diskarbitrationd"
        ]
        if signingIds.contains(signingId) { return true }
        return executablePath == "/usr/bin/hdiutil"
            || executablePath == "/usr/libexec/diskarbitrationd"
            || executablePath.hasSuffix("/diskimagemounter.app/contents/macos/diskimagemounter")
            || executablePath.hasSuffix("/diskimages.framework/versions/a/resources/diskimages-helper")
    }
}
