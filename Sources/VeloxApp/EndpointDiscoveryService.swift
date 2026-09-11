import Darwin
import Foundation
import UniformTypeIdentifiers
import VeloxCore

struct EndpointDiscoveryFinding: Codable, Sendable, Equatable {
    let filePath: String
    let fileName: String
    let fileType: String
    let contentHashPrefix: String
    let locationKind: String
    let classifications: [String]
    let ruleIds: [String]
    let matchCount: Int
    let tagStatus: String
    let durationMillis: Int
    let fileSize: Int64?
    let modifiedAtSeconds: Int64?
    let modifiedAtNanoseconds: Int64?
}

struct EndpointDiscoveryReport: Codable, Sendable, Equatable {
    let ok: Bool
    let scanId: String
    let trigger: String
    let status: String
    let startedAt: String
    let completedAt: String
    let policyVersion: Int
    let rootsScanned: Int
    let filesEnumerated: Int
    let filesInspected: Int
    let filesSkipped: Int
    let inaccessibleItems: Int
    let findingsCount: Int
    let taggedCount: Int
    let tagFailureCount: Int
    let durationMillis: Int
    let reportPath: String?
    let findings: [EndpointDiscoveryFinding]
    let findingsTruncated: Bool
    let message: String?

    func limitedForConsole(maxFindings: Int = 100) -> EndpointDiscoveryReport {
        EndpointDiscoveryReport(
            ok: ok,
            scanId: scanId,
            trigger: trigger,
            status: status,
            startedAt: startedAt,
            completedAt: completedAt,
            policyVersion: policyVersion,
            rootsScanned: rootsScanned,
            filesEnumerated: filesEnumerated,
            filesInspected: filesInspected,
            filesSkipped: filesSkipped,
            inaccessibleItems: inaccessibleItems,
            findingsCount: findingsCount,
            taggedCount: taggedCount,
            tagFailureCount: tagFailureCount,
            durationMillis: durationMillis,
            reportPath: reportPath,
            findings: Array(findings.prefix(maxFindings)),
            findingsTruncated: findingsTruncated || findings.count > maxFindings,
            message: message
        )
    }
}

struct EndpointDiscoveryRuntimeStatus: Codable, Sendable, Equatable {
    let ok: Bool
    let running: Bool
    let currentScanId: String?
    let lastReport: EndpointDiscoveryReport?
    let nextScheduledAt: String?
    let reportDirectory: String
    let message: String?
}

private struct EndpointDiscoveryEventPayload: Codable {
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

/// Runs scheduled and on-demand at-rest scans in the logged-in host process.
/// Full Disk Access applies to this process; the Endpoint Security extension
/// remains the policy authority and receives validated, content-free events.
final class EndpointDiscoveryService: @unchecked Sendable {
    static let classificationAttribute = "com.velox.macdlp.classification"

    private struct ScanRoot {
        let url: URL
        let kind: String
    }

    private struct ClassificationTag: Codable {
        let policyVersion: Int
        let scanId: String
        let timestamp: String
        let classifications: [String]
        let ruleIds: [String]
        let contentHashPrefix: String
    }

    private let ocrService: OCRService
    private let controlClient: ExtensionControlClient
    private let fileManager: FileManager
    private let homeDirectory: URL
    private let policyPath: String
    private let reportDirectory: URL
    private let scanQueue = DispatchQueue(label: "co.velox.macdlp.discovery", qos: .utility)
    private let lock = NSLock()
    private var timer: DispatchSourceTimer?
    private var running = false
    private var currentScanId: String?
    private var lastReport: EndpointDiscoveryReport?
    private var lastSyncedScanId: String?

    init(
        ocrService: OCRService,
        controlClient: ExtensionControlClient,
        fileManager: FileManager = .default,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser,
        policyPath: String = PolicyManager.defaultPolicyPath,
        reportDirectory: URL? = nil
    ) {
        self.ocrService = ocrService
        self.controlClient = controlClient
        self.fileManager = fileManager
        self.homeDirectory = homeDirectory.standardizedFileURL
        self.policyPath = policyPath
        self.reportDirectory = reportDirectory ?? homeDirectory
            .appendingPathComponent("Library/Application Support/VeloxMacDLP/Discovery/Reports", isDirectory: true)
        self.lastReport = Self.loadLatestReport(
            fileManager: fileManager,
            reportDirectory: self.reportDirectory
        )
    }

    func startScheduler() {
        lock.lock()
        guard timer == nil else {
            lock.unlock()
            return
        }
        let timer = DispatchSource.makeTimerSource(queue: scanQueue)
        timer.schedule(deadline: .now() + 15, repeating: 60, leeway: .seconds(5))
        timer.setEventHandler { [weak self] in self?.evaluateSchedule() }
        self.timer = timer
        lock.unlock()
        timer.resume()
        syncLatestClassificationsIfNeeded()
    }

    func stopScheduler() {
        lock.lock()
        let timer = self.timer
        self.timer = nil
        lock.unlock()
        timer?.cancel()
    }

    @discardableResult
    func startScan(trigger: String = "manual") -> EndpointDiscoveryRuntimeStatus {
        let normalizedTrigger = trigger == "scheduled" ? "scheduled" : "manual"
        guard let policy = loadPolicy() else {
            return status(message: "The active discovery policy could not be loaded.")
        }
        guard policy.endpointDiscoveryControl.mode != .disabled else {
            return status(message: "Endpoint Data Discovery is disabled.")
        }

        lock.lock()
        guard !running else {
            lock.unlock()
            return status(message: "A discovery scan is already running.")
        }
        let scanId = UUID().uuidString.lowercased()
        running = true
        currentScanId = scanId
        lock.unlock()

        scanQueue.async { [weak self] in
            self?.runScan(scanId: scanId, trigger: normalizedTrigger, policy: policy)
        }
        return status(message: "Endpoint data discovery scan started.")
    }

    func status(message: String? = nil) -> EndpointDiscoveryRuntimeStatus {
        lock.lock()
        let running = self.running
        let currentScanId = self.currentScanId
        let report = self.lastReport?.limitedForConsole()
        lock.unlock()

        let nextScheduledAt: String?
        if let policy = loadPolicy(),
           policy.endpointDiscoveryControl.mode != .disabled,
           let completedAt = lastReportDate(report) {
            nextScheduledAt = Self.timestamp(
                completedAt.addingTimeInterval(
                    TimeInterval(policy.endpointDiscoveryControl.scheduleIntervalMinutes * 60)
                )
            )
        } else {
            nextScheduledAt = nil
        }
        return EndpointDiscoveryRuntimeStatus(
            ok: true,
            running: running,
            currentScanId: currentScanId,
            lastReport: report,
            nextScheduledAt: nextScheduledAt,
            reportDirectory: reportDirectory.path,
            message: message
        )
    }

    private func evaluateSchedule() {
        guard let policy = loadPolicy(),
              policy.endpointDiscoveryControl.mode != .disabled else { return }
        lock.lock()
        let alreadyRunning = running
        let report = lastReport
        lock.unlock()
        guard !alreadyRunning else { return }

        if let lastDate = lastReportDate(report),
           Date().timeIntervalSince(lastDate) < TimeInterval(
               policy.endpointDiscoveryControl.scheduleIntervalMinutes * 60
           ) {
            return
        }
        _ = startScan(trigger: "scheduled")
    }

    private func runScan(scanId: String, trigger: String, policy: VeloxPolicy) {
        let started = Date()
        let config = policy.endpointDiscoveryControl
        let roots = discoverRoots(config: config)
        var filesEnumerated = 0
        var filesInspected = 0
        var filesSkipped = 0
        var inaccessibleItems = 0
        var taggedCount = 0
        var tagFailureCount = 0
        var findings: [EndpointDiscoveryFinding] = []

        for root in roots {
            guard filesEnumerated < config.maxFilesPerScan else { break }
            guard let enumerator = fileManager.enumerator(
                at: root.url,
                includingPropertiesForKeys: [
                    .isRegularFileKey,
                    .isReadableKey,
                    .isSymbolicLinkKey,
                    .fileSizeKey,
                    .contentTypeKey
                ],
                options: [.skipsHiddenFiles, .skipsPackageDescendants],
                errorHandler: { _, _ in
                    inaccessibleItems += 1
                    return true
                }
            ) else {
                inaccessibleItems += 1
                continue
            }

            while let url = enumerator.nextObject() as? URL {
                if shouldSkipDirectory(url) {
                    enumerator.skipDescendants()
                    continue
                }
                guard filesEnumerated < config.maxFilesPerScan else { break }
                guard let values = try? url.resourceValues(forKeys: [
                    .isRegularFileKey,
                    .isReadableKey,
                    .isSymbolicLinkKey,
                    .fileSizeKey,
                    .contentTypeKey
                ]) else {
                    inaccessibleItems += 1
                    continue
                }
                guard values.isRegularFile == true, values.isSymbolicLink != true else { continue }
                filesEnumerated += 1

                guard values.isReadable != false,
                      isSupportedContentType(values.contentType, pathExtension: url.pathExtension),
                      (values.fileSize ?? 0) <= policy.ocrControl.maxFileSizeMB * 1_048_576 else {
                    filesSkipped += 1
                    continue
                }

                do {
                    guard let metadataBefore = Self.fileMetadata(atPath: url.path) else {
                        inaccessibleItems += 1
                        continue
                    }
                    let report = try ocrService.analyzeSync(
                        url: url,
                        config: policy.ocrControl,
                        mode: config.mode,
                        source: "discovery"
                    )
                    filesInspected += 1
                    guard !report.matches.isEmpty else { continue }
                    guard let metadataAfter = Self.fileMetadata(atPath: url.path),
                          metadataAfter == metadataBefore else {
                        filesSkipped += 1
                        continue
                    }

                    let tagStatus: String
                    if config.mode == .enforce && config.tagClassifiedFiles {
                        if writeClassificationTag(
                            url: url,
                            scanId: scanId,
                            policyVersion: policy.policyVersion,
                            report: report
                        ) {
                            tagStatus = "tagged"
                            taggedCount += 1
                        } else {
                            tagStatus = "tag-failed"
                            tagFailureCount += 1
                        }
                    } else {
                        tagStatus = "audited"
                    }

                    let finding = EndpointDiscoveryFinding(
                        filePath: url.path,
                        fileName: url.lastPathComponent,
                        fileType: report.fileType,
                        contentHashPrefix: report.contentHashPrefix,
                        locationKind: root.kind,
                        classifications: report.matches.map(\.classification),
                        ruleIds: report.matches.map(\.ruleId),
                        matchCount: report.matches.reduce(0) { $0 + $1.matchCount },
                        tagStatus: tagStatus,
                        durationMillis: report.durationMillis,
                        fileSize: metadataAfter.fileSize,
                        modifiedAtSeconds: metadataAfter.modifiedAtSeconds,
                        modifiedAtNanoseconds: metadataAfter.modifiedAtNanoseconds
                    )
                    findings.append(finding)
                    recordFinding(finding, scanId: scanId, trigger: trigger)
                } catch OCRServiceError.unsupportedFileType {
                    filesSkipped += 1
                } catch OCRServiceError.noRecognizableContent {
                    filesInspected += 1
                } catch {
                    inaccessibleItems += 1
                }
            }
        }

        let completed = Date()
        let reportPath = reportDirectory.appendingPathComponent("\(scanId).json").path
        var report = EndpointDiscoveryReport(
            ok: true,
            scanId: scanId,
            trigger: trigger,
            status: "completed",
            startedAt: Self.timestamp(started),
            completedAt: Self.timestamp(completed),
            policyVersion: policy.policyVersion,
            rootsScanned: roots.count,
            filesEnumerated: filesEnumerated,
            filesInspected: filesInspected,
            filesSkipped: filesSkipped,
            inaccessibleItems: inaccessibleItems,
            findingsCount: findings.count,
            taggedCount: taggedCount,
            tagFailureCount: tagFailureCount,
            durationMillis: Int(completed.timeIntervalSince(started) * 1_000),
            reportPath: reportPath,
            findings: findings,
            findingsTruncated: false,
            message: inaccessibleItems > 0
                ? "Scan completed with \(inaccessibleItems) inaccessible item(s). Full Disk Access may be required for complete coverage."
                : "Scan completed successfully."
        )
        do {
            try persist(report: report)
        } catch {
            report = EndpointDiscoveryReport(
                ok: false,
                scanId: report.scanId,
                trigger: report.trigger,
                status: report.status,
                startedAt: report.startedAt,
                completedAt: report.completedAt,
                policyVersion: report.policyVersion,
                rootsScanned: report.rootsScanned,
                filesEnumerated: report.filesEnumerated,
                filesInspected: report.filesInspected,
                filesSkipped: report.filesSkipped,
                inaccessibleItems: report.inaccessibleItems,
                findingsCount: report.findingsCount,
                taggedCount: report.taggedCount,
                tagFailureCount: report.tagFailureCount,
                durationMillis: report.durationMillis,
                reportPath: nil,
                findings: report.findings,
                findingsTruncated: report.findingsTruncated,
                message: "Scan completed, but the report could not be saved: \(error.localizedDescription)"
            )
        }

        recordSummary(report)
        lock.lock()
        lastReport = report
        running = false
        currentScanId = nil
        lock.unlock()
        syncLatestClassificationsIfNeeded()
    }

    private func loadPolicy() -> VeloxPolicy? {
        guard let data = try? Data(
            contentsOf: URL(fileURLWithPath: policyPath),
            options: [.mappedIfSafe]
        ) else { return nil }
        return try? VeloxPolicy.decodeStrict(from: data)
    }

    private func discoverRoots(config: EndpointDiscoveryControlConfig) -> [ScanRoot] {
        var roots: [ScanRoot] = []
        var seen = Set<String>()
        func add(_ url: URL, kind: String) {
            let standardized = url.standardizedFileURL
            guard seen.insert(standardized.path).inserted else { return }
            roots.append(ScanRoot(url: standardized, kind: kind))
        }

        if config.includeLocalHome {
            add(homeDirectory, kind: "local-home")
        }
        guard config.includeMountedVolumes || config.includeMountedShares else { return roots }
        let keys: Set<URLResourceKey> = [
            .volumeIsLocalKey,
            .volumeIsInternalKey,
            .volumeIsRemovableKey,
            .volumeIsBrowsableKey
        ]
        let mounted = fileManager.mountedVolumeURLs(
            includingResourceValuesForKeys: Array(keys),
            options: [.skipHiddenVolumes]
        ) ?? []
        for volume in mounted where volume.path != "/" && !volume.path.hasPrefix(homeDirectory.path + "/") {
            guard let values = try? volume.resourceValues(forKeys: keys),
                  values.volumeIsBrowsable != false else { continue }
            if values.volumeIsLocal == false {
                if config.includeMountedShares { add(volume, kind: "mounted-share") }
            } else if config.includeMountedVolumes,
                      values.volumeIsRemovable == true || values.volumeIsInternal == false {
                add(volume, kind: "mounted-volume")
            }
        }
        return roots
    }

    private func shouldSkipDirectory(_ url: URL) -> Bool {
        let name = url.lastPathComponent.lowercased()
        let ignoredNames: Set<String> = [
            ".git", ".build", ".trash", "node_modules", "caches", "deriveddata"
        ]
        if ignoredNames.contains(name) { return true }
        let path = url.standardizedFileURL.path
        return path == reportDirectory.deletingLastPathComponent().path ||
            path.hasPrefix(reportDirectory.deletingLastPathComponent().path + "/")
    }

    private func isSupportedContentType(_ type: UTType?, pathExtension: String) -> Bool {
        let resolved = type ?? UTType(filenameExtension: pathExtension)
        return resolved?.conforms(to: .image) == true ||
            resolved?.conforms(to: .pdf) == true ||
            resolved?.conforms(to: .text) == true
    }

    private func writeClassificationTag(
        url: URL,
        scanId: String,
        policyVersion: Int,
        report: OCRScanReport
    ) -> Bool {
        let tag = ClassificationTag(
            policyVersion: policyVersion,
            scanId: scanId,
            timestamp: Self.timestamp(Date()),
            classifications: Array(report.matches.map(\.classification).prefix(32)),
            ruleIds: Array(report.matches.map(\.ruleId).prefix(32)),
            contentHashPrefix: report.contentHashPrefix
        )
        guard let data = try? JSONEncoder().encode(tag) else { return false }
        return data.withUnsafeBytes { bytes in
            url.path.withCString { path in
                Self.classificationAttribute.withCString { attribute in
                    setxattr(path, attribute, bytes.baseAddress, data.count, 0, 0) == 0
                }
            }
        }
    }

    private func recordFinding(_ finding: EndpointDiscoveryFinding, scanId: String, trigger: String) {
        recordEvent(EndpointDiscoveryEventPayload(
            kind: "finding",
            scanId: scanId,
            trigger: trigger,
            filePath: finding.filePath,
            fileType: finding.fileType,
            contentHashPrefix: finding.contentHashPrefix,
            locationKind: finding.locationKind,
            ruleIds: finding.ruleIds,
            classifications: finding.classifications,
            tagStatus: finding.tagStatus,
            durationMillis: finding.durationMillis,
            filesEnumerated: nil,
            filesInspected: nil,
            findingsCount: nil,
            taggedCount: nil,
            inaccessibleItems: nil,
            status: nil
            ,fileSize: finding.fileSize
            ,modifiedAtSeconds: finding.modifiedAtSeconds
            ,modifiedAtNanoseconds: finding.modifiedAtNanoseconds
        ))
    }

    private func recordSummary(_ report: EndpointDiscoveryReport) {
        recordEvent(EndpointDiscoveryEventPayload(
            kind: "summary",
            scanId: report.scanId,
            trigger: report.trigger,
            filePath: nil,
            fileType: nil,
            contentHashPrefix: nil,
            locationKind: nil,
            ruleIds: [],
            classifications: [],
            tagStatus: nil,
            durationMillis: report.durationMillis,
            filesEnumerated: report.filesEnumerated,
            filesInspected: report.filesInspected,
            findingsCount: report.findingsCount,
            taggedCount: report.taggedCount,
            inaccessibleItems: report.inaccessibleItems,
            status: report.ok ? "completed" : "report-failed"
            ,fileSize: nil
            ,modifiedAtSeconds: nil
            ,modifiedAtNanoseconds: nil
        ))
    }

    private struct FileMetadata: Equatable {
        let fileSize: Int64
        let modifiedAtSeconds: Int64
        let modifiedAtNanoseconds: Int64
    }

    private static func fileMetadata(atPath path: String) -> FileMetadata? {
        var info = stat()
        guard path.withCString({ lstat($0, &info) }) == 0 else { return nil }
        return FileMetadata(
            fileSize: Int64(info.st_size),
            modifiedAtSeconds: Int64(info.st_mtimespec.tv_sec),
            modifiedAtNanoseconds: Int64(info.st_mtimespec.tv_nsec)
        )
    }

    private func syncLatestClassificationsIfNeeded() {
        lock.lock()
        let report = lastReport
        let alreadySynced = report?.scanId == lastSyncedScanId
        lock.unlock()
        guard let report, !alreadySynced, !report.findings.isEmpty else { return }

        let records = report.findings.compactMap { finding -> FileClassificationRecord? in
            guard let fileSize = finding.fileSize,
                  let seconds = finding.modifiedAtSeconds,
                  let nanoseconds = finding.modifiedAtNanoseconds else { return nil }
            return FileClassificationRecord(
                filePath: finding.filePath,
                fileSize: fileSize,
                modifiedAtSeconds: seconds,
                modifiedAtNanoseconds: nanoseconds,
                contentHashPrefix: finding.contentHashPrefix,
                classifications: finding.classifications,
                ruleIds: finding.ruleIds,
                policyVersion: report.policyVersion
            )
        }
        guard !records.isEmpty else { return }
        let encoder = JSONEncoder()
        for offset in stride(from: 0, to: records.count, by: 250) {
            let chunk = Array(records[offset..<min(offset + 250, records.count)])
            guard let data = try? encoder.encode(chunk),
                  let json = String(data: data, encoding: .utf8) else { continue }
            controlClient.syncEndpointDiscoveryClassifications(json) { [weak self] response in
                guard response.contains("\"ok\":true") else { return }
                self?.lock.lock()
                self?.lastSyncedScanId = report.scanId
                self?.lock.unlock()
            }
        }
    }

    private func recordEvent(_ payload: EndpointDiscoveryEventPayload) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(payload),
              let json = String(data: data, encoding: .utf8) else { return }
        controlClient.recordEndpointDiscoveryEvent(json) { _ in }
    }

    private func persist(report: EndpointDiscoveryReport) throws {
        try fileManager.createDirectory(
            at: reportDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(report)
        let reportURL = reportDirectory.appendingPathComponent("\(report.scanId).json")
        let latestURL = reportDirectory.appendingPathComponent("latest.json")
        try data.write(to: reportURL, options: .atomic)
        try data.write(to: latestURL, options: .atomic)
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: reportURL.path)
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: latestURL.path)
    }

    private static func loadLatestReport(
        fileManager: FileManager,
        reportDirectory: URL
    ) -> EndpointDiscoveryReport? {
        let url = reportDirectory.appendingPathComponent("latest.json")
        guard fileManager.fileExists(atPath: url.path),
              let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(EndpointDiscoveryReport.self, from: data)
    }

    private func lastReportDate(_ report: EndpointDiscoveryReport?) -> Date? {
        guard let value = report?.completedAt else { return nil }
        let fractionalFormatter = ISO8601DateFormatter()
        fractionalFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = fractionalFormatter.date(from: value) {
            return date
        }
        return ISO8601DateFormatter().date(from: value)
    }

    private static func timestamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }
}
