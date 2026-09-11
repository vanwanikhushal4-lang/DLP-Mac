import Darwin
import XCTest
@testable import VeloxCore

final class ClassifiedEgressControlTests: XCTestCase {
    private let path = "/Users/alice/Documents/aadhaar.png"

    private func policy(
        mode: PolicyMode = .enforce,
        channels: [ClassifiedEgressChannel] = ClassifiedEgressChannel.allCases,
        protected: [String] = []
    ) -> VeloxPolicy {
        VeloxPolicy(
            policyVersion: 12,
            applicationControl: ApplicationControlConfig(mode: .disabled),
            ocrControl: OCRControlConfig(
                egressMode: mode,
                protectedEgressChannels: channels,
                protectedEgressClassifications: protected
            )
        )
    }

    private func record(
        classification: String,
        ruleId: String,
        policyVersion: Int = 12
    ) -> FileClassificationRecord {
        FileClassificationRecord(
            filePath: path,
            fileSize: 256,
            modifiedAtSeconds: 1_000,
            modifiedAtNanoseconds: 42,
            contentHashPrefix: "abcdef123456",
            classifications: [classification],
            ruleIds: [ruleId],
            policyVersion: policyVersion
        )
    }

    func testAllFourDefaultClassificationsAreBlockedOnEveryProtectedChannel() {
        let engine = PolicyEngine(policy: policy())
        let classifications = [
            ("Payment Card Data", "ocr-payment-card"),
            ("Indian Tax Identifier", "ocr-indian-pan"),
            ("Indian Identity Data", "ocr-aadhaar"),
            ("Confidential Document", "ocr-confidential-keywords")
        ]

        for channel in ClassifiedEgressChannel.allCases {
            for (classification, ruleId) in classifications {
                let decision = engine.evaluateClassifiedEgress(
                    channel: channel,
                    classification: record(classification: classification, ruleId: ruleId)
                )
                XCTAssertEqual(decision.decisionString, "blocked")
                XCTAssertFalse(decision.shouldAllow)
                XCTAssertEqual(decision.classifications, [classification])
                XCTAssertFalse(decision.requiresClassification)
            }
        }
    }

    func testUnknownAndStaleFilesAreHeldForClassification() {
        let engine = PolicyEngine(policy: policy())
        for value in [
            engine.evaluateClassifiedEgress(channel: .webUpload, classification: nil),
            engine.evaluateClassifiedEgress(
                channel: .usb,
                classification: record(
                    classification: "Confidential Document",
                    ruleId: "ocr-confidential-keywords",
                    policyVersion: 11
                )
            )
        ] {
            XCTAssertEqual(value.decisionString, "blocked")
            XCTAssertTrue(value.requiresClassification)
            XCTAssertEqual(value.matchingRuleId, "content-egress-classification-required")
        }
    }

    func testCleanClassificationAllowsTransferAndSelectedProtectionIsHonored() {
        let engine = PolicyEngine(policy: policy(protected: ["Indian Identity Data"]))
        let clean = FileClassificationRecord(
            filePath: path,
            fileSize: 256,
            modifiedAtSeconds: 1_000,
            modifiedAtNanoseconds: 42,
            contentHashPrefix: "abcdef123456",
            classifications: [],
            ruleIds: [],
            policyVersion: 12
        )
        XCTAssertTrue(engine.evaluateClassifiedEgress(channel: .email, classification: clean).shouldAllow)
        XCTAssertTrue(engine.evaluateClassifiedEgress(
            channel: .email,
            classification: record(classification: "Payment Card Data", ruleId: "ocr-payment-card")
        ).shouldAllow)
        XCTAssertFalse(engine.evaluateClassifiedEgress(
            channel: .email,
            classification: record(classification: "Indian Identity Data", ruleId: "ocr-aadhaar")
        ).shouldAllow)
    }

    func testAuditAndDisabledChannelNeverDeny() {
        let audit = PolicyEngine(policy: policy(mode: .auditOnly))
            .evaluateClassifiedEgress(channel: .nearbyTransfer, classification: nil)
        XCTAssertTrue(audit.shouldAllow)
        XCTAssertEqual(audit.decisionString, "would-block")
        XCTAssertTrue(audit.requiresClassification)

        let omitted = PolicyEngine(policy: policy(channels: [.usb]))
            .evaluateClassifiedEgress(channel: .webUpload, classification: nil)
        XCTAssertTrue(omitted.shouldAllow)
        XCTAssertFalse(omitted.isCandidate)
    }

    func testOpenRouteAttributionSeparatesDownloadsFromOutboundReads() {
        let engine = PolicyEngine(policy: policy())
        let safari = ProcessContext(
            pid: 100,
            parentPid: 1,
            uid: 501,
            signingId: "com.apple.Safari",
            teamId: nil,
            isPlatformBinary: true,
            cdhash: nil,
            executablePath: "/Applications/Safari.app/Contents/MacOS/Safari"
        )
        XCTAssertEqual(engine.classifiedEgressChannelForOpen(
            process: safari,
            filePath: path,
            requestedFlags: UInt32(FREAD),
            isRegularFile: true
        ), .webUpload)
        XCTAssertNil(engine.classifiedEgressChannelForOpen(
            process: safari,
            filePath: path,
            requestedFlags: UInt32(FWRITE),
            isRegularFile: true
        ))
    }

    func testLegacyPolicyDefaultsClassifiedEgressToDisabled() throws {
        let data = Data(#"{"policyVersion":1,"applicationControl":{"mode":"disabled"}}"#.utf8)
        let decoded = try VeloxPolicy.decodeStrict(from: data)
        XCTAssertEqual(decoded.ocrControl.egressMode, .disabled)
        XCTAssertEqual(decoded.ocrControl.protectedEgressChannels, ClassifiedEgressChannel.allCases)
    }
}
