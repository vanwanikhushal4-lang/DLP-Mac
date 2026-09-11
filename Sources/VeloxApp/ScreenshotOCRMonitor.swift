import Foundation
import VeloxCore
import os.log

/// Receives file-create candidates attributed by Endpoint Security to Apple's
/// signed screenshot tools, waits for the file to become stable, then performs
/// detect-and-remediate OCR. It never claims pre-capture screenshot prevention.
final class ScreenshotOCRMonitor: @unchecked Sendable {
    private let logger = Logger(subsystem: "co.velox.macdlp", category: "ScreenshotOCR")
    private let queue = DispatchQueue(label: "co.velox.macdlp.screenshot-ocr", qos: .utility)
    private let ocrService: OCRService
    private let controlClient: ExtensionControlClient
    private var inFlightPaths = Set<String>()

    init(ocrService: OCRService, controlClient: ExtensionControlClient) {
        self.ocrService = ocrService
        self.controlClient = controlClient
    }

    func processCandidate(path: String) {
        queue.async { [weak self] in
            guard let self else { return }
            let normalizedPath = URL(fileURLWithPath: path).standardizedFileURL.path
            guard self.inFlightPaths.insert(normalizedPath).inserted else { return }
            guard self.waitForStableFile(atPath: normalizedPath) else {
                self.inFlightPaths.remove(normalizedPath)
                return
            }
            guard let policy = self.loadPolicy(), policy.ocrControl.screenshotMode != .disabled else {
                self.inFlightPaths.remove(normalizedPath)
                return
            }

            self.ocrService.analyze(
                url: URL(fileURLWithPath: normalizedPath),
                config: policy.ocrControl,
                mode: policy.ocrControl.screenshotMode,
                source: "screenshot"
            ) { [weak self] result in
                guard let self else { return }
                self.queue.async {
                    defer { self.inFlightPaths.remove(normalizedPath) }
                    switch result {
                    case .success(let report):
                        var remediation: String? = nil
                        if report.decision == "blocked" && !report.matches.isEmpty {
                            remediation = self.remediateScreenshot(
                                atPath: normalizedPath,
                                method: policy.ocrControl.screenshotRemediation,
                                hashPrefix: report.contentHashPrefix
                            )
                        }
                        self.record(report: report, remediation: remediation)
                    case .failure(let error):
                        self.logger.error(
                            "Screenshot OCR failed for \(normalizedPath, privacy: .private): \(error.localizedDescription, privacy: .public)"
                        )
                    }
                }
            }
        }
    }

    private func waitForStableFile(atPath path: String) -> Bool {
        var priorSize: UInt64?
        var stablePasses = 0
        for _ in 0..<20 {
            if let attributes = try? FileManager.default.attributesOfItem(atPath: path),
               let number = attributes[.size] as? NSNumber,
               number.uint64Value > 0 {
                let size = number.uint64Value
                if size == priorSize {
                    stablePasses += 1
                    if stablePasses >= 2 { return true }
                } else {
                    priorSize = size
                    stablePasses = 0
                }
            }
            usleep(200_000)
        }
        return false
    }

    private func loadPolicy() -> VeloxPolicy? {
        guard let data = try? Data(
            contentsOf: URL(fileURLWithPath: PolicyManager.defaultPolicyPath),
            options: [.mappedIfSafe]
        ) else { return nil }
        return try? VeloxPolicy.decodeStrict(from: data)
    }

    private func remediateScreenshot(
        atPath path: String,
        method: OCRScreenshotRemediation,
        hashPrefix: String
    ) -> String {
        let sourceURL = URL(fileURLWithPath: path)
        do {
            switch method {
            case .delete:
                try FileManager.default.removeItem(at: sourceURL)
                logger.warning("Deleted a screenshot classified as sensitive.")
                return "deleted"
            case .quarantine:
                let base = try FileManager.default.url(
                    for: .applicationSupportDirectory,
                    in: .userDomainMask,
                    appropriateFor: nil,
                    create: true
                )
                let quarantine = base
                    .appendingPathComponent("VeloxMacDLP", isDirectory: true)
                    .appendingPathComponent("Quarantine", isDirectory: true)
                    .appendingPathComponent("Screenshots", isDirectory: true)
                try FileManager.default.createDirectory(
                    at: quarantine,
                    withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700]
                )
                let destination = quarantine.appendingPathComponent(
                    "screenshot-\(hashPrefix).\(sourceURL.pathExtension.lowercased())"
                )
                if FileManager.default.fileExists(atPath: destination.path) {
                    try FileManager.default.removeItem(at: sourceURL)
                } else {
                    try FileManager.default.moveItem(at: sourceURL, to: destination)
                }
                logger.warning("Quarantined a screenshot classified as sensitive.")
                return "quarantined"
            }
        } catch {
            logger.error("Screenshot remediation failed: \(error.localizedDescription, privacy: .public)")
            return "remediation-failed"
        }
    }

    private func record(report: OCRScanReport, remediation: String?) {
        let payload: [String: Any] = [
            "source": report.source,
            "fileType": report.fileType,
            "contentHashPrefix": report.contentHashPrefix,
            "decision": report.decision,
            "ruleIds": report.matches.map(\.ruleId),
            "classifications": report.matches.map(\.classification),
            "recognizedCharacterCount": report.recognizedCharacterCount,
            "pageCount": report.pageCount,
            "averageConfidence": report.averageConfidence,
            "usedOCR": report.usedOCR,
            "cacheHit": report.cacheHit,
            "durationMillis": report.durationMillis,
            "remediation": remediation ?? "none"
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
              let json = String(data: data, encoding: .utf8) else { return }
        controlClient.recordOCRScanEvent(json) { _ in }
    }
}
