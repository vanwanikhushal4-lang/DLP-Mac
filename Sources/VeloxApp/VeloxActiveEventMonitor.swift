import Foundation
import VeloxCore
import os.log

/// Actively monitors the real-time activity log (/Library/Logs/VeloxMacDLP/events.jsonl)
/// using Darwin file descriptor events and timer polling fallback.
/// When a blocked event occurs, it immediately:
/// 1. Posts a native macOS system notification (via VeloxNotificationManager).
/// 2. Pushes the live event into the Web Console (via ConsoleController).
public final class VeloxActiveEventMonitor: @unchecked Sendable {
    private let logger = Logger(subsystem: "co.velox.macdlp", category: "ActiveMonitor")
    private let logPath: String
    private let queue = DispatchQueue(label: "co.velox.macdlp.activemonitor", qos: .utility)
    private var fileDescriptor: Int32 = -1
    private var dispatchSource: DispatchSourceFileSystemObject?
    private var pollTimer: DispatchSourceTimer?
    private var currentFileOffset: off_t = 0
    private var remainderBuffer: String = ""
    private var isRunning = false
    private let decoder = JSONDecoder()

    public init(logPath: String = EventLogger.defaultLogPath) {
        self.logPath = logPath
    }

    deinit {
        stop()
    }

    public func start() {
        queue.async { [weak self] in
            guard let self, !self.isRunning else { return }
            self.isRunning = true
            self.openLogFileAndSeekToEnd()
            self.setupDispatchSource()
            self.setupPollingFallback()
            self.logger.info("VeloxActiveEventMonitor started watching \(self.logPath, privacy: .public)")
        }
    }

    public func stop() {
        queue.async { [weak self] in
            guard let self, self.isRunning else { return }
            self.isRunning = false
            self.dispatchSource?.cancel()
            self.dispatchSource = nil
            self.pollTimer?.cancel()
            self.pollTimer = nil
            if self.fileDescriptor >= 0 {
                close(self.fileDescriptor)
                self.fileDescriptor = -1
            }
            self.logger.info("VeloxActiveEventMonitor stopped.")
        }
    }

    private func openLogFileAndSeekToEnd() {
        if fileDescriptor >= 0 {
            close(fileDescriptor)
            fileDescriptor = -1
        }

        fileDescriptor = open(logPath, O_RDONLY)
        if fileDescriptor < 0 {
            logger.debug("Active monitor: log file not found yet at \(self.logPath, privacy: .public)")
            currentFileOffset = 0
            return
        }

        // Seek directly to end of file on startup so we only capture NEW live events
        let endOffset = lseek(fileDescriptor, 0, SEEK_END)
        currentFileOffset = max(0, endOffset)
        remainderBuffer = ""
        logger.info("Active monitor attached at EOF offset \(self.currentFileOffset)")
    }

    private func setupDispatchSource() {
        guard fileDescriptor >= 0 else { return }
        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fileDescriptor,
            eventMask: [.write, .extend, .attrib],
            queue: queue
        )
        source.setEventHandler { [weak self] in
            self?.readNewEvents()
        }
        source.setCancelHandler {
            // Clean up
        }
        source.resume()
        self.dispatchSource = source
    }

    private func setupPollingFallback() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 0.5, repeating: 0.5)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            if self.fileDescriptor < 0 {
                self.openLogFileAndSeekToEnd()
                if self.fileDescriptor >= 0 {
                    self.setupDispatchSource()
                }
            } else {
                self.readNewEvents()
            }
        }
        timer.resume()
        self.pollTimer = timer
    }

    private func readNewEvents() {
        guard fileDescriptor >= 0 else { return }

        var fileStat = stat()
        if fstat(fileDescriptor, &fileStat) != 0 {
            return
        }

        let currentFileSize = fileStat.st_size
        if currentFileSize < currentFileOffset {
            // File was truncated or rotated
            currentFileOffset = 0
            remainderBuffer = ""
        }

        guard currentFileSize > currentFileOffset else { return }

        let bytesToRead = Int(currentFileSize - currentFileOffset)
        var buffer = [UInt8](repeating: 0, count: bytesToRead)

        let bytesRead = pread(fileDescriptor, &buffer, bytesToRead, currentFileOffset)
        guard bytesRead > 0 else { return }

        currentFileOffset += off_t(bytesRead)

        guard let chunk = String(bytes: buffer.prefix(bytesRead), encoding: .utf8) else { return }
        let combined = remainderBuffer + chunk
        let lines = combined.components(separatedBy: "\n")

        if combined.hasSuffix("\n") {
            remainderBuffer = ""
            for line in lines where !line.isEmpty {
                processLogLine(line)
            }
        } else {
            if let last = lines.last {
                remainderBuffer = last
            }
            for line in lines.dropLast() where !line.isEmpty {
                processLogLine(line)
            }
        }
    }

    private func processLogLine(_ line: String) {
        guard let data = line.data(using: .utf8),
              let event = try? decoder.decode(ExecutionEvent.self, from: data) else {
            return
        }

        // 1. Immediately stream the live event to the in-app Web Console
        Task { @MainActor in
            ConsoleController.current?.broadcastLiveEvent(event)
        }

        // 2. If blocked, immediately trigger the native macOS Notification Center alert
        if event.decision == "blocked" {
            let target = event.resourcePath ?? event.executablePath
            let detail: String
            if event.module == "network-flow-control" {
                detail = event.executablePath
            } else if event.module == "ocr-content-classification" {
                detail = event.classifications?.joined(separator: ", ") ?? ""
            } else {
                detail = event.signingId ?? event.teamId ?? ""
            }
            VeloxNotificationManager.shared.postBlockedNotification(
                module: event.module,
                action: event.action,
                target: target,
                detail: detail
            )
            logger.info("Active monitor triggered notification for blocked event: \(event.module, privacy: .public) - \(target, privacy: .public)")
        }
    }
}
