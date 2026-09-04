import Foundation
import os

public struct ExecutionEvent: Codable, Sendable, Equatable {
    public let timestamp: String
    public let eventId: String
    public let module: String
    public let action: String
    public let decision: String
    public let ruleId: String?
    public let policyVersion: Int
    public let executablePath: String
    public let signingId: String?
    public let teamId: String?
    public let pid: Int32
    public let parentPid: Int32
    public let uid: UInt32
    public let decisionLatencyMicros: UInt64

    public init(
        timestamp: String? = nil,
        eventId: String = UUID().uuidString,
        module: String = "application-control",
        action: String = "exec",
        decision: String,
        ruleId: String?,
        policyVersion: Int,
        executablePath: String,
        signingId: String?,
        teamId: String?,
        pid: Int32,
        parentPid: Int32,
        uid: UInt32,
        decisionLatencyMicros: UInt64
    ) {
        if let ts = timestamp {
            self.timestamp = ts
        } else {
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            self.timestamp = formatter.string(from: Date())
        }
        self.eventId = eventId
        self.module = module
        self.action = action
        self.decision = decision
        self.ruleId = ruleId
        self.policyVersion = policyVersion
        self.executablePath = executablePath
        self.signingId = signingId
        self.teamId = teamId
        self.pid = pid
        self.parentPid = parentPid
        self.uid = uid
        self.decisionLatencyMicros = decisionLatencyMicros
    }
}

public final class EventLogger: @unchecked Sendable {
    public static let defaultLogPath = "/Library/Logs/VeloxMacDLP/events.jsonl"
    public static let maxQueueSize: Int = 10_000
    public static let maxFileSizeBytes: UInt64 = 10 * 1024 * 1024 // 10 MB
    public static let maxBackupFiles: Int = 5

    private let logFilePath: String
    private let queue: DispatchQueue
    private var fileHandle: FileHandle?
    private let encoder: JSONEncoder

    private let queueCounterLock = os_unfair_lock_t.allocate(capacity: 1)
    private var inFlightEventsCount: Int = 0
    private var droppedEventsCount: UInt64 = 0

    public init(logFilePath: String = EventLogger.defaultLogPath) {
        self.logFilePath = logFilePath
        self.queue = DispatchQueue(label: "co.velox.macdlp.logger", qos: .utility)
        self.encoder = JSONEncoder()
        self.encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        self.queueCounterLock.initialize(to: os_unfair_lock())
        ensureLogDirectoryExists()
    }

    deinit {
        flushSync()
        try? fileHandle?.close()
        queueCounterLock.deallocate()
    }

    private func ensureLogDirectoryExists() {
        let dir = (logFilePath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [
            .posixPermissions: 0o755
        ])
    }

    private func getOrCreateHandle() -> FileHandle? {
        if let handle = self.fileHandle {
            return handle
        }
        ensureLogDirectoryExists()
        if !FileManager.default.fileExists(atPath: logFilePath) {
            FileManager.default.createFile(atPath: logFilePath, contents: nil, attributes: [
                .posixPermissions: 0o644
            ])
        }
        let handle = FileHandle(forWritingAtPath: logFilePath)
        handle?.seekToEndOfFile()
        self.fileHandle = handle
        return handle
    }

    /// Logs an event asynchronously on a background queue with bounded backpressure.
    /// If the queue exceeds `maxQueueSize`, excess events are safely shed to protect memory.
    public func logEventAsync(_ event: ExecutionEvent) {
        os_unfair_lock_lock(queueCounterLock)
        if inFlightEventsCount >= EventLogger.maxQueueSize {
            droppedEventsCount += 1
            os_unfair_lock_unlock(queueCounterLock)
            fputs("[VeloxEventLogger] Backpressure warning: In-flight logging queue full. Event shed.\n", stderr)
            return
        }
        inFlightEventsCount += 1
        os_unfair_lock_unlock(queueCounterLock)

        queue.async { [weak self] in
            guard let self = self else { return }
            self.writeEvent(event)

            os_unfair_lock_lock(self.queueCounterLock)
            self.inFlightEventsCount -= 1
            os_unfair_lock_unlock(self.queueCounterLock)
        }
    }

    /// Logs an event synchronously (used during testing, shutdown, and critical errors).
    public func logEventSync(_ event: ExecutionEvent) {
        queue.sync {
            self.writeEvent(event)
        }
    }

    /// Flushes any pending log writes to disk.
    public func flushSync() {
        queue.sync {
            try? self.fileHandle?.synchronize()
        }
    }

    private func writeEvent(_ event: ExecutionEvent) {
        // Check for file rotation before write
        checkRotationIfNeeded()

        do {
            var data = try encoder.encode(event)
            data.append(contentsOf: [0x0a]) // \n
            if let handle = getOrCreateHandle() {
                handle.write(data)
            }
        } catch {
            fputs("[VeloxEventLogger] Error encoding event: \(error)\n", stderr)
        }
    }

    private func checkRotationIfNeeded() {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: logFilePath),
              let size = attrs[.size] as? UInt64,
              size >= EventLogger.maxFileSizeBytes else {
            return
        }

        // Close current handle
        try? fileHandle?.synchronize()
        try? fileHandle?.close()
        fileHandle = nil

        let fm = FileManager.default
        // Rotate existing backups: e.g. .4 -> .5, .3 -> .4, etc.
        for i in stride(from: EventLogger.maxBackupFiles - 1, through: 1, by: -1) {
            let src = "\(logFilePath).\(i)"
            let dst = "\(logFilePath).\(i + 1)"
            if fm.fileExists(atPath: src) {
                try? fm.removeItem(atPath: dst)
                try? fm.moveItem(atPath: src, toPath: dst)
            }
        }

        // Rotate current log to .1
        let firstBackup = "\(logFilePath).1"
        try? fm.removeItem(atPath: firstBackup)
        try? fm.moveItem(atPath: logFilePath, toPath: firstBackup)

        // Create new empty log file
        fm.createFile(atPath: logFilePath, contents: nil, attributes: [
            .posixPermissions: 0o644
        ])
    }
}
