import Darwin
import XCTest
@testable import VeloxCore

final class EmailAttachmentControlTests: XCTestCase {
    private let path = "/Users/alice/Documents/confidential.pdf"

    private func policy(
        mode: PolicyMode = .enforce,
        protected: [String] = []
    ) -> VeloxPolicy {
        VeloxPolicy(
            policyVersion: 7,
            applicationControl: ApplicationControlConfig(mode: .disabled),
            emailAttachmentControl: EmailAttachmentControlConfig(
                mode: mode,
                protectedClassifications: protected
            )
        )
    }

    private func appleMail() -> ProcessContext {
        ProcessContext(
            pid: 501,
            parentPid: 1,
            uid: 501,
            signingId: "com.apple.mail",
            teamId: nil,
            isPlatformBinary: true,
            cdhash: nil,
            executablePath: "/System/Applications/Mail.app/Contents/MacOS/Mail"
        )
    }

    private func record(classification: String = "Confidential Document") -> FileClassificationRecord {
        FileClassificationRecord(
            filePath: path,
            fileSize: 128,
            modifiedAtSeconds: 100,
            modifiedAtNanoseconds: 20,
            contentHashPrefix: "abcdef123456",
            classifications: [classification],
            ruleIds: [classification == "Confidential Document" ? "ocr-confidential-keywords" : "ocr-payment-card"],
            policyVersion: 7
        )
    }

    func testLegacyPolicyDefaultsEmailControlToDisabled() throws {
        let data = #"{"policyVersion":1,"applicationControl":{"mode":"disabled"}}"#.data(using: .utf8)!
        let decoded = try VeloxPolicy.decodeStrict(from: data)
        XCTAssertEqual(decoded.emailAttachmentControl.mode, .disabled)
        XCTAssertEqual(decoded.emailAttachmentControl.mailClients.count, 2)
    }

    func testClassifiedReadByAppleMailIsBlocked() {
        let decision = PolicyEngine(policy: policy()).evaluateEmailAttachmentOpen(
            process: appleMail(),
            filePath: path,
            requestedFlags: UInt32(FREAD),
            isRegularFile: true,
            classification: record()
        )
        XCTAssertEqual(decision.decisionString, "blocked")
        XCTAssertFalse(decision.shouldAllowOpen)
        XCTAssertEqual(decision.mailClientName, "Apple Mail")
        XCTAssertEqual(decision.classifications, ["Confidential Document"])
    }

    func testDownloadsAndUnclassifiedFilesRemainAllowed() {
        let engine = PolicyEngine(policy: policy())
        let download = engine.evaluateEmailAttachmentOpen(
            process: appleMail(), filePath: path,
            requestedFlags: UInt32(FREAD | FWRITE), isRegularFile: true,
            classification: record()
        )
        let unclassified = engine.evaluateEmailAttachmentOpen(
            process: appleMail(), filePath: path,
            requestedFlags: UInt32(FREAD), isRegularFile: true,
            classification: nil
        )
        XCTAssertTrue(download.shouldAllowOpen)
        XCTAssertFalse(download.isAttachmentCandidate)
        XCTAssertTrue(unclassified.shouldAllowOpen)
    }

    func testSelectedClassificationAndAuditMode() {
        let engine = PolicyEngine(policy: policy(mode: .auditOnly, protected: ["Payment Card Data"]))
        let unrelated = engine.evaluateEmailAttachmentOpen(
            process: appleMail(), filePath: path,
            requestedFlags: UInt32(FREAD), isRegularFile: true,
            classification: record()
        )
        let selected = engine.evaluateEmailAttachmentOpen(
            process: appleMail(), filePath: path,
            requestedFlags: UInt32(FREAD), isRegularFile: true,
            classification: record(classification: "Payment Card Data")
        )
        XCTAssertFalse(unrelated.isAttachmentCandidate)
        XCTAssertEqual(selected.decisionString, "would-block")
        XCTAssertTrue(selected.shouldAllowOpen)
    }

    func testCacheRejectsStaleMetadata() {
        let cache = FileClassificationCache(maximumRecordCount: 10)
        cache.upsert([record()])
        XCTAssertNotNil(cache.lookup(filePath: path, fileSize: 128, modifiedAtSeconds: 100, modifiedAtNanoseconds: 20))
        XCTAssertNil(cache.lookup(filePath: path, fileSize: 129, modifiedAtSeconds: 100, modifiedAtNanoseconds: 20))
        XCTAssertEqual(cache.count, 0)
    }

    func testStrictPolicyRejectsUnknownEmailPropertyAndInsecureClient() {
        let unknown = #"{"policyVersion":1,"applicationControl":{"mode":"disabled"},"emailAttachmentControl":{"mode":"enforce","mailClients":[{"ruleId":"mail","signingId":"com.apple.mail","isPlatformBinary":true}],"protectedClassifications":[],"recipient":"outside"}}"#
        XCTAssertThrowsError(try VeloxPolicy.decodeStrict(from: Data(unknown.utf8)))

        let insecure = EmailAttachmentControlConfig(
            mode: .enforce,
            mailClients: [ApplicationRule(ruleId: "spoofable", signingId: "example.mail")]
        )
        XCTAssertThrowsError(try insecure.validate())
    }

    func testEmailNotificationContainsClientAndClassification() {
        let formatted = VeloxNotificationFormatter.format(
            module: "email-attachment-control",
            action: "native-mail-classified-file-read",
            target: path,
            detail: "Apple Mail|Confidential Document"
        )
        XCTAssertEqual(formatted.title, "Blocked by Velox DLP")
        XCTAssertEqual(formatted.subtitle, "Email Attachment Blocked")
        XCTAssertTrue(formatted.body.contains("Apple Mail"))
        XCTAssertTrue(formatted.body.contains("Confidential Document"))
    }
}
