import Darwin
import Foundation
import XCTest
import VeloxCore

final class EndpointDiscoveryServiceTests: XCTestCase {
    func testPlainTextClassificationUsesExistingRules() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("velox-discovery-\(UUID().uuidString).txt")
        try Data("CONFIDENTIAL 4111 1111 1111 1111".utf8).write(to: url, options: .atomic)
        defer { try? FileManager.default.removeItem(at: url) }

        let report = try OCRService().analyzeSync(
            url: url,
            config: OCRControlConfig(mode: .enforce),
            mode: .auditOnly,
            source: "discovery"
        )

        XCTAssertFalse(report.usedOCR)
        XCTAssertEqual(report.decision, "would-block")
        XCTAssertTrue(report.matches.contains { $0.ruleId == "ocr-confidential-keywords" })
        XCTAssertTrue(report.matches.contains { $0.ruleId == "ocr-payment-card" })
    }

    func testEnforceScanClassifiesTagsAndPersistsContentFreeReport() throws {
        let fileManager = FileManager.default
        let root = fileManager.temporaryDirectory
            .appendingPathComponent("velox-discovery-service-\(UUID().uuidString)", isDirectory: true)
        let homeDirectory = root.appendingPathComponent("home", isDirectory: true)
        let reportDirectory = root
            .appendingPathComponent("report-storage", isDirectory: true)
            .appendingPathComponent("reports", isDirectory: true)
        let policyURL = root.appendingPathComponent("policy.json")
        let sensitiveURL = homeDirectory.appendingPathComponent("customer-record.txt")
        let cleanURL = homeDirectory.appendingPathComponent("readme.txt")
        try fileManager.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? fileManager.removeItem(at: root) }

        let rawSensitiveContent = "CONFIDENTIAL 4111 1111 1111 1111"
        try Data(rawSensitiveContent.utf8).write(to: sensitiveURL, options: .atomic)
        try Data("ordinary public notes".utf8).write(to: cleanURL, options: .atomic)

        let policy = VeloxPolicy(
            policyVersion: 42,
            applicationControl: ApplicationControlConfig(
                mode: .auditOnly,
                blockedApplications: [],
                allowedApplications: []
            ),
            ocrControl: OCRControlConfig(mode: .enforce),
            endpointDiscoveryControl: EndpointDiscoveryControlConfig(
                mode: .enforce,
                scheduleIntervalMinutes: 1_440,
                includeLocalHome: true,
                includeMountedVolumes: false,
                includeMountedShares: false,
                tagClassifiedFiles: true,
                maxFilesPerScan: 100
            )
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try encoder.encode(policy).write(to: policyURL, options: .atomic)

        let service = EndpointDiscoveryService(
            ocrService: OCRService(),
            controlClient: ExtensionControlClient(),
            fileManager: fileManager,
            homeDirectory: homeDirectory,
            policyPath: policyURL.path,
            reportDirectory: reportDirectory
        )
        XCTAssertTrue(service.startScan().running)

        let deadline = Date().addingTimeInterval(5)
        var status = service.status()
        while status.running && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
            status = service.status()
        }

        XCTAssertFalse(status.running, "The bounded discovery scan did not finish")
        let report = try XCTUnwrap(status.lastReport)
        XCTAssertTrue(report.ok)
        XCTAssertEqual(report.status, "completed")
        XCTAssertEqual(report.policyVersion, 42)
        XCTAssertEqual(report.rootsScanned, 1)
        XCTAssertEqual(report.filesEnumerated, 2)
        XCTAssertEqual(report.filesInspected, 2)
        XCTAssertEqual(report.findingsCount, 1)
        XCTAssertEqual(report.taggedCount, 1)
        XCTAssertEqual(report.tagFailureCount, 0)
        XCTAssertTrue(
            report.findings.first?.filePath.hasSuffix("/home/customer-record.txt") == true
        )
        XCTAssertEqual(report.findings.first?.tagStatus, "tagged")

        let tagData = try readExtendedAttribute(
            EndpointDiscoveryService.classificationAttribute,
            from: sensitiveURL
        )
        let tagObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: tagData) as? [String: Any]
        )
        XCTAssertEqual(tagObject["policyVersion"] as? Int, 42)
        XCTAssertFalse(String(decoding: tagData, as: UTF8.self).contains(rawSensitiveContent))

        let latestURL = reportDirectory.appendingPathComponent("latest.json")
        let persistedReport = try Data(contentsOf: latestURL)
        XCTAssertFalse(String(decoding: persistedReport, as: UTF8.self).contains(rawSensitiveContent))
        let permissions = try fileManager.attributesOfItem(atPath: latestURL.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(permissions?.intValue, 0o600)
    }

    private func readExtendedAttribute(_ name: String, from url: URL) throws -> Data {
        let size = url.path.withCString { path in
            name.withCString { attribute in
                getxattr(path, attribute, nil, 0, 0, 0)
            }
        }
        guard size >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        var data = Data(count: size)
        let result = data.withUnsafeMutableBytes { bytes in
            url.path.withCString { path in
                name.withCString { attribute in
                    getxattr(path, attribute, bytes.baseAddress, size, 0, 0)
                }
            }
        }
        guard result == size else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        return data
    }
}
