import Foundation
import os

/// Metadata-bound discovery result used by real-time controls. No extracted
/// content is retained. A changed file never inherits an old classification.
public struct FileClassificationRecord: Codable, Sendable, Equatable {
    public let filePath: String
    public let fileSize: Int64
    public let modifiedAtSeconds: Int64
    public let modifiedAtNanoseconds: Int64
    public let contentHashPrefix: String
    public let classifications: [String]
    public let ruleIds: [String]
    public let policyVersion: Int

    public init(
        filePath: String,
        fileSize: Int64,
        modifiedAtSeconds: Int64,
        modifiedAtNanoseconds: Int64,
        contentHashPrefix: String,
        classifications: [String],
        ruleIds: [String],
        policyVersion: Int
    ) {
        self.filePath = filePath
        self.fileSize = fileSize
        self.modifiedAtSeconds = modifiedAtSeconds
        self.modifiedAtNanoseconds = modifiedAtNanoseconds
        self.contentHashPrefix = contentHashPrefix
        self.classifications = classifications
        self.ruleIds = ruleIds
        self.policyVersion = policyVersion
    }
}

/// Bounded, thread-safe, in-memory cache suitable for an Endpoint Security
/// authorization callback. Lookups are O(1) and perform no filesystem I/O.
public final class FileClassificationCache: @unchecked Sendable {
    private let lock = os_unfair_lock_t.allocate(capacity: 1)
    private var records: [String: FileClassificationRecord] = [:]
    private let maximumRecordCount: Int

    public init(maximumRecordCount: Int = 100_000) {
        self.maximumRecordCount = max(1, maximumRecordCount)
        lock.initialize(to: os_unfair_lock())
    }

    deinit { lock.deallocate() }

    public var count: Int {
        os_unfair_lock_lock(lock)
        defer { os_unfair_lock_unlock(lock) }
        return records.count
    }

    public func upsert(_ newRecords: [FileClassificationRecord]) {
        guard !newRecords.isEmpty else { return }
        os_unfair_lock_lock(lock)
        defer { os_unfair_lock_unlock(lock) }

        for record in newRecords where record.filePath.hasPrefix("/") {
            records[record.filePath] = record
        }
        if records.count > maximumRecordCount {
            let overflow = records.count - maximumRecordCount
            for key in records.keys.sorted().prefix(overflow) {
                records.removeValue(forKey: key)
            }
        }
    }

    /// Returns a record only if its immutable identity still matches the file
    /// observed in the AUTH_OPEN message. A mismatch evicts the stale result.
    public func lookup(
        filePath: String,
        fileSize: Int64,
        modifiedAtSeconds: Int64,
        modifiedAtNanoseconds: Int64
    ) -> FileClassificationRecord? {
        os_unfair_lock_lock(lock)
        defer { os_unfair_lock_unlock(lock) }
        guard let record = records[filePath] else { return nil }
        guard record.fileSize == fileSize,
              record.modifiedAtSeconds == modifiedAtSeconds,
              record.modifiedAtNanoseconds == modifiedAtNanoseconds else {
            records.removeValue(forKey: filePath)
            return nil
        }
        return record
    }

    public func retainValid(ruleIds: Set<String>, classifications: Set<String>) {
        os_unfair_lock_lock(lock)
        defer { os_unfair_lock_unlock(lock) }
        records = records.filter { _, record in
            zip(record.ruleIds, record.classifications).contains { ruleId, classification in
                ruleIds.contains(ruleId) && classifications.contains(classification.lowercased())
            }
        }
    }
}
