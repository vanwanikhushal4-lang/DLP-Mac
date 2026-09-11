import Darwin
import Foundation
import VeloxCore
import os.log

/// Classifies a file only after Endpoint Security has returned its first
/// content-egress decision. A second attempt uses the metadata-bound cache.
final class EgressClassificationCoordinator: @unchecked Sendable {
    private struct Identity: Equatable {
        let size: Int64
        let modifiedSeconds: Int64
        let modifiedNanoseconds: Int64
    }

    private let logger = Logger(subsystem: "co.velox.macdlp", category: "EgressClassifier")
    private let queue = DispatchQueue(label: "co.velox.macdlp.egress-classifier", qos: .userInitiated)
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
            let normalized = URL(fileURLWithPath: path).standardizedFileURL.path
            guard normalized.hasPrefix("/"), self.inFlightPaths.insert(normalized).inserted else { return }
            guard let identity = self.identity(at: normalized) else {
                self.recordFailure(path: normalized, reasonCode: "file-inaccessible")
                self.inFlightPaths.remove(normalized)
                return
            }
            guard let policy = self.loadPolicy() else {
                self.recordFailure(path: normalized, reasonCode: "policy-unavailable")
                self.inFlightPaths.remove(normalized)
                return
            }
            guard policy.ocrControl.egressMode != .disabled else {
                self.inFlightPaths.remove(normalized)
                return
            }

            self.ocrService.analyze(
                url: URL(fileURLWithPath: normalized),
                config: policy.ocrControl,
                mode: policy.ocrControl.egressMode,
                source: "egress"
            ) { [weak self] result in
                guard let self else { return }
                self.queue.async {
                    switch result {
                    case .success(let report):
                        guard self.identity(at: normalized) == identity else {
                            self.logger.notice("Discarded egress classification because the file changed during analysis.")
                            self.recordFailure(
                                path: normalized,
                                reasonCode: "file-changed-during-scan"
                            )
                            self.inFlightPaths.remove(normalized)
                            return
                        }
                        let record = FileClassificationRecord(
                            filePath: normalized,
                            fileSize: identity.size,
                            modifiedAtSeconds: identity.modifiedSeconds,
                            modifiedAtNanoseconds: identity.modifiedNanoseconds,
                            contentHashPrefix: report.contentHashPrefix,
                            classifications: report.matches.map(\.classification),
                            ruleIds: report.matches.map(\.ruleId),
                            policyVersion: policy.policyVersion
                        )
                        self.sync(record: record) { accepted in
                            self.queue.async {
                                defer { self.inFlightPaths.remove(normalized) }
                                if accepted {
                                    self.record(report: report)
                                } else {
                                    self.recordFailure(
                                        path: normalized,
                                        reasonCode: "cache-sync-rejected"
                                    )
                                }
                            }
                        }
                    case .failure(let error):
                        self.logger.error(
                            "Egress classification failed: \(error.localizedDescription, privacy: .public)"
                        )
                        self.recordFailure(
                            path: normalized,
                            reasonCode: self.reasonCode(for: error)
                        )
                        self.inFlightPaths.remove(normalized)
                    }
                }
            }
        }
    }

    private func identity(at path: String) -> Identity? {
        var value = stat()
        guard lstat(path, &value) == 0,
              value.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) else { return nil }
        return Identity(
            size: Int64(value.st_size),
            modifiedSeconds: Int64(value.st_mtimespec.tv_sec),
            modifiedNanoseconds: Int64(value.st_mtimespec.tv_nsec)
        )
    }

    private func loadPolicy() -> VeloxPolicy? {
        guard let data = try? Data(
            contentsOf: URL(fileURLWithPath: PolicyManager.defaultPolicyPath),
            options: [.mappedIfSafe]
        ) else { return nil }
        return try? VeloxPolicy.decodeStrict(from: data)
    }

    private func sync(
        record: FileClassificationRecord,
        completion: @escaping @Sendable (Bool) -> Void
    ) {
        guard let data = try? JSONEncoder().encode([record]),
              let json = String(data: data, encoding: .utf8) else {
            completion(false)
            return
        }
        controlClient.syncEndpointDiscoveryClassifications(json) { response in
            guard let data = response.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  object["ok"] as? Bool == true else {
                completion(false)
                return
            }
            completion(true)
        }
    }

    private func recordFailure(path: String, reasonCode: String) {
        controlClient.recordEgressClassificationFailure(
            filePath: path,
            reasonCode: reasonCode
        ) { _ in }
    }

    private func reasonCode(for error: Error) -> String {
        guard let error = error as? OCRServiceError else { return "analysis-error" }
        switch error {
        case .inaccessibleFile: return "file-inaccessible"
        case .unsupportedFileType: return "unsupported-file-type"
        case .oversizedFile: return "file-too-large"
        case .tooManyPDFPages: return "pdf-page-limit-exceeded"
        case .unreadableImage: return "image-unreadable"
        case .unreadablePDF: return "pdf-unreadable"
        case .noRecognizableContent: return "no-recognizable-content"
        }
    }

    private func record(report: OCRScanReport) {
        let payload: [String: Any] = [
            "source": "egress",
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
            "remediation": "cached-for-egress"
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
              let json = String(data: data, encoding: .utf8) else { return }
        controlClient.recordOCRScanEvent(json) { _ in }
    }
}
