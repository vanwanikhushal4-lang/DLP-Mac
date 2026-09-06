import Darwin
import Foundation
import VeloxCore
import os.log

struct PrinterControlRuntimeSnapshot: Sendable {
    let discoveredQueueCount: Int
    let controlledQueueCount: Int
    let lastError: String?
}

private struct ManagedPrinterState: Codable, Sendable, Equatable {
    let wasEnabled: Bool
    let wasAcceptingJobs: Bool
}

private struct CUPSCommandResult: Sendable {
    let terminationStatus: Int32
    let output: String

    var succeeded: Bool { terminationStatus == 0 }
}

/// Root-side CUPS queue enforcement for the Printer Control prototype.
///
/// Enforce mode rejects new jobs, stops every configured queue, and cancels
/// already queued jobs. Original queue state is persisted before mutation and
/// only queues changed by Velox are restored when enforcement is disabled.
final class PrinterControlCoordinator: @unchecked Sendable {
    static let defaultStatePath = "/Library/Application Support/VeloxMacDLP/printer-state.json"

    private let policyEngine: PolicyEngine
    private let eventLogger: EventLogger
    private let statePath: String
    private let workQueue = DispatchQueue(label: "co.velox.macdlp.printer-control", qos: .utility)
    private let snapshotLock = NSLock()
    private let logger = Logger(subsystem: "co.velox.macdlp.endpointsecurity", category: "PrinterControl")

    private var timer: DispatchSourceTimer?
    private var managedQueues: [String: ManagedPrinterState] = [:]
    private var observedJobIdentifiers = Set<String>()
    private var currentSnapshot = PrinterControlRuntimeSnapshot(
        discoveredQueueCount: 0,
        controlledQueueCount: 0,
        lastError: nil
    )

    var onBlockedEvent: (@Sendable (ExecutionEvent) -> Void)?

    init(
        policyEngine: PolicyEngine,
        eventLogger: EventLogger,
        statePath: String = PrinterControlCoordinator.defaultStatePath
    ) {
        self.policyEngine = policyEngine
        self.eventLogger = eventLogger
        self.statePath = statePath
    }

    func start() {
        workQueue.async { [weak self] in
            guard let self, self.timer == nil else { return }
            self.loadManagedState()
            self.reconcile()

            let timer = DispatchSource.makeTimerSource(queue: self.workQueue)
            timer.schedule(deadline: .now() + 1, repeating: 1, leeway: .milliseconds(100))
            timer.setEventHandler { [weak self] in
                self?.reconcile()
            }
            self.timer = timer
            timer.resume()
        }
    }

    func stop() {
        workQueue.sync {
            timer?.cancel()
            timer = nil
        }
    }

    func policyDidChange() {
        workQueue.async { [weak self] in
            self?.reconcile()
        }
    }

    /// Used by the authenticated policy mutation path so the response reflects
    /// the queue state after enforcement has actually been attempted.
    func reconcileNow() {
        workQueue.sync {
            reconcile()
        }
    }

    func snapshot() -> PrinterControlRuntimeSnapshot {
        snapshotLock.lock()
        defer { snapshotLock.unlock() }
        return currentSnapshot
    }

    private func reconcile() {
        let policy = policyEngine.currentPolicy()
        let config = policy.printerControl

        do {
            let queues = try discoverQueues()
            switch config.mode {
            case .enforce where config.blockAllPrinters:
                try enforce(queues: queues, policyVersion: policy.policyVersion)
                observedJobIdentifiers.removeAll()
            case .auditOnly where config.blockAllPrinters:
                try restoreManagedQueues(from: queues, policyVersion: policy.policyVersion)
                try auditJobs(policyVersion: policy.policyVersion)
            case .disabled, .enforce, .auditOnly:
                try restoreManagedQueues(from: queues, policyVersion: policy.policyVersion)
                observedJobIdentifiers.removeAll()
            }

            publishSnapshot(
                discoveredQueueCount: queues.count,
                controlledQueueCount: managedQueues.count,
                lastError: nil
            )
        } catch {
            let message = String(describing: error)
            logger.error("Printer reconciliation failed: \(message, privacy: .public)")
            publishSnapshot(
                discoveredQueueCount: snapshot().discoveredQueueCount,
                controlledQueueCount: managedQueues.count,
                lastError: message
            )
        }
    }

    private func discoverQueues() throws -> [PrinterQueueSnapshot] {
        let printerResult = try run("/usr/bin/lpstat", arguments: ["-p"])
        let acceptingResult = try run("/usr/bin/lpstat", arguments: ["-a"])

        let printerEmpty = PrinterQueueParser.isNoDestinationsMessage(printerResult.output)
        let acceptingEmpty = PrinterQueueParser.isNoDestinationsMessage(acceptingResult.output)
        guard printerResult.succeeded || printerEmpty else {
            throw PrinterControlError.commandFailed("lpstat -p", printerResult)
        }
        guard acceptingResult.succeeded || acceptingEmpty else {
            throw PrinterControlError.commandFailed("lpstat -a", acceptingResult)
        }

        return PrinterQueueParser.queues(
            printersOutput: printerResult.output,
            acceptingOutput: acceptingResult.output
        )
    }

    private func enforce(queues: [PrinterQueueSnapshot], policyVersion: Int) throws {
        let availableNames = Set(queues.map(\.name))
        let removedManagedNames = Set(managedQueues.keys).subtracting(availableNames)
        if !removedManagedNames.isEmpty {
            for name in removedManagedNames { managedQueues.removeValue(forKey: name) }
            persistManagedState()
        }

        for queue in queues where queue.isEnabled || queue.isAcceptingJobs {
            if managedQueues[queue.name] == nil {
                managedQueues[queue.name] = ManagedPrinterState(
                    wasEnabled: queue.isEnabled,
                    wasAcceptingJobs: queue.isAcceptingJobs
                )
                // Persist original state before changing the system queue.
                try persistManagedStateThrowing()
            }

            if queue.isAcceptingJobs {
                let result = try run(
                    "/usr/sbin/cupsreject",
                    arguments: ["-r", "Blocked by Velox DLP policy", queue.name]
                )
                guard result.succeeded else {
                    throw PrinterControlError.commandFailed("cupsreject \(queue.name)", result)
                }
            }

            if queue.isEnabled {
                let result = try run(
                    "/usr/sbin/cupsdisable",
                    arguments: ["-c", "-r", "Blocked by Velox DLP policy", queue.name]
                )
                guard result.succeeded else {
                    throw PrinterControlError.commandFailed("cupsdisable \(queue.name)", result)
                }
            }

            let event = printerEvent(
                action: "queue-disabled",
                decision: "blocked",
                policyVersion: policyVersion,
                queueName: queue.name,
                result: "cups-rejected-disabled-jobs-cancelled"
            )
            eventLogger.logEventAsync(event)
            onBlockedEvent?(event)
        }
    }

    private func restoreManagedQueues(
        from queues: [PrinterQueueSnapshot],
        policyVersion: Int
    ) throws {
        guard !managedQueues.isEmpty else { return }
        let queueByName = Dictionary(uniqueKeysWithValues: queues.map { ($0.name, $0) })

        for name in managedQueues.keys.sorted() {
            guard let original = managedQueues[name] else { continue }
            guard let current = queueByName[name] else {
                managedQueues.removeValue(forKey: name)
                continue
            }

            if original.wasAcceptingJobs && !current.isAcceptingJobs {
                let result = try run("/usr/sbin/cupsaccept", arguments: [name])
                guard result.succeeded else {
                    throw PrinterControlError.commandFailed("cupsaccept \(name)", result)
                }
            }

            if original.wasEnabled && !current.isEnabled {
                let result = try run("/usr/sbin/cupsenable", arguments: [name])
                guard result.succeeded else {
                    throw PrinterControlError.commandFailed("cupsenable \(name)", result)
                }
            }

            managedQueues.removeValue(forKey: name)
            eventLogger.logEventAsync(
                printerEvent(
                    action: "queue-restored",
                    decision: "allowed",
                    policyVersion: policyVersion,
                    queueName: name,
                    result: "restored-velox-managed-state"
                )
            )
        }
        try persistManagedStateThrowing()
    }

    private func auditJobs(policyVersion: Int) throws {
        let result = try run("/usr/bin/lpstat", arguments: ["-W", "not-completed", "-o"])
        if !result.succeeded && !PrinterQueueParser.isNoDestinationsMessage(result.output) {
            throw PrinterControlError.commandFailed("lpstat print jobs", result)
        }

        let jobs = PrinterQueueParser.jobs(from: result.output)
        let activeIdentifiers = Set(jobs.map(\.identifier))
        for job in jobs where !observedJobIdentifiers.contains(job.identifier) {
            eventLogger.logEventAsync(
                printerEvent(
                    action: "print-job-observed",
                    decision: "would-block",
                    policyVersion: policyVersion,
                    queueName: job.queueName,
                    result: "cups-audit-job"
                )
            )
        }
        observedJobIdentifiers = activeIdentifiers
    }

    private func printerEvent(
        action: String,
        decision: String,
        policyVersion: Int,
        queueName: String,
        result: String
    ) -> ExecutionEvent {
        ExecutionEvent(
            module: "printer-control",
            action: action,
            decision: decision,
            ruleId: "printer-block-all",
            policyVersion: policyVersion,
            executablePath: "/usr/sbin/cupsd",
            signingId: "com.apple.cupsd",
            teamId: nil,
            pid: 0,
            parentPid: 0,
            uid: 0,
            decisionLatencyMicros: 1,
            authResponseResult: result,
            resourcePath: queueName,
            interaction: "physical-printer"
        )
    }

    private func run(_ executable: String, arguments: [String]) throws -> CUPSCommandResult {
        let process = Process()
        let outputPipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = outputPipe
        process.standardError = outputPipe
        var environment = ProcessInfo.processInfo.environment
        environment["LC_ALL"] = "C"
        environment["LANG"] = "C"
        process.environment = environment

        try process.run()
        process.waitUntilExit()
        let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
        return CUPSCommandResult(
            terminationStatus: process.terminationStatus,
            output: String(decoding: data, as: UTF8.self)
        )
    }

    private func loadManagedState() {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: statePath)),
              let decoded = try? JSONDecoder().decode([String: ManagedPrinterState].self, from: data) else {
            return
        }
        managedQueues = decoded
    }

    private func persistManagedState() {
        do {
            try persistManagedStateThrowing()
        } catch {
            logger.error("Unable to persist printer restoration state: \(String(describing: error), privacy: .public)")
        }
    }

    private func persistManagedStateThrowing() throws {
        let directory = (statePath as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(
            atPath: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755]
        )
        let data = try JSONEncoder().encode(managedQueues)
        try data.write(to: URL(fileURLWithPath: statePath), options: .atomic)
        _ = chmod(statePath, 0o600)
    }

    private func publishSnapshot(
        discoveredQueueCount: Int,
        controlledQueueCount: Int,
        lastError: String?
    ) {
        snapshotLock.lock()
        currentSnapshot = PrinterControlRuntimeSnapshot(
            discoveredQueueCount: discoveredQueueCount,
            controlledQueueCount: controlledQueueCount,
            lastError: lastError
        )
        snapshotLock.unlock()
    }
}

private enum PrinterControlError: Error, CustomStringConvertible {
    case commandFailed(String, CUPSCommandResult)

    var description: String {
        switch self {
        case .commandFailed(let operation, let result):
            let output = result.output
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .prefix(512)
            return "\(operation) failed with status \(result.terminationStatus): \(output)"
        }
    }
}
