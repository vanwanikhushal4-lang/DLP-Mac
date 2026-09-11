import XCTest
@testable import VeloxCore

final class OCRClassifierTests: XCTestCase {
    func testDefaultRulesClassifySensitiveIdentifiersWithoutReturningRawText() throws {
        let text = "CONFIDENTIAL account 4111 1111 1111 1111 PAN ABCDE1234F Aadhaar 2345 6789 0124"
        let config = OCRControlConfig(mode: .enforce)

        let verdict = OCRClassifier.evaluate(text: text, config: config)

        XCTAssertEqual(verdict.decision, "blocked")
        XCTAssertEqual(
            Set(verdict.matches.map(\.ruleId)),
            Set(["ocr-payment-card", "ocr-indian-pan", "ocr-aadhaar", "ocr-confidential-keywords"])
        )
        let encoded = String(decoding: try JSONEncoder().encode(verdict), as: UTF8.self)
        XCTAssertFalse(encoded.contains("4111"))
        XCTAssertFalse(encoded.contains("ABCDE1234F"))
        XCTAssertFalse(encoded.contains("2345 6789"))
    }

    func testInvalidCheckDigitsAreNotClassified() {
        let config = OCRControlConfig(
            mode: .enforce,
            rules: [
                OCRClassificationRule(
                    ruleId: "card",
                    name: "Card",
                    classification: "Payment Card Data",
                    type: .creditCard
                ),
                OCRClassificationRule(
                    ruleId: "aadhaar",
                    name: "Aadhaar",
                    classification: "Indian Identity Data",
                    type: .aadhaar
                )
            ]
        )

        let verdict = OCRClassifier.evaluate(
            text: "Card 4111 1111 1111 1112 and Aadhaar 2345 6789 0123",
            config: config
        )

        XCTAssertEqual(verdict.decision, "allowed")
        XCTAssertTrue(verdict.matches.isEmpty)
    }

    func testKeywordAndRegexRulesHonorMinimumMatches() {
        let config = OCRControlConfig(
            mode: .auditOnly,
            rules: [
                OCRClassificationRule(
                    ruleId: "secret-words",
                    name: "Secret words",
                    classification: "Internal",
                    type: .keyword,
                    keywords: ["internal only"],
                    minimumMatches: 2
                ),
                OCRClassificationRule(
                    ruleId: "employee-id",
                    name: "Employee ID",
                    classification: "Employee Data",
                    type: .regularExpression,
                    pattern: #"EMP-[0-9]{4}"#
                )
            ]
        )

        let verdict = OCRClassifier.evaluate(
            text: "Internal Only / internal only / EMP-2048",
            config: config
        )

        XCTAssertEqual(verdict.decision, "would-block")
        XCTAssertEqual(verdict.matches.map(\.matchCount), [2, 1])
    }

    func testDisabledModeReportsMatchesButDoesNotBlock() {
        let verdict = OCRClassifier.evaluate(
            text: "RESTRICTED",
            config: OCRControlConfig(mode: .disabled)
        )

        XCTAssertEqual(verdict.decision, "allowed")
        XCTAssertEqual(verdict.matches.first?.ruleId, "ocr-confidential-keywords")
    }

    func testLegacyPolicyDefaultsOCRToDisabled() throws {
        let data = Data(#"{"policyVersion":1,"applicationControl":{"mode":"disabled"}}"#.utf8)
        let policy = try VeloxPolicy.decodeStrict(from: data)

        XCTAssertEqual(policy.ocrControl.mode, .disabled)
        XCTAssertEqual(policy.ocrControl.screenshotMode, .disabled)
        XCTAssertEqual(policy.ocrControl.rules.count, 4)
    }

    func testOCRStrictDecodingRejectsUnknownProperties() {
        let data = Data(#"{"policyVersion":1,"applicationControl":{"mode":"disabled"},"ocrControl":{"mode":"enforce","unknown":true}}"#.utf8)

        XCTAssertThrowsError(try VeloxPolicy.decodeStrict(from: data)) { error in
            guard case PolicyValidationError.unknownProperty = error else {
                return XCTFail("Expected unknownProperty, got \(error)")
            }
        }
    }

    func testOCRValidationRejectsDuplicateRuleIdsAndBadRegex() {
        let duplicate = OCRClassificationRule(
            ruleId: "same",
            name: "One",
            classification: "Secret",
            type: .keyword,
            keywords: ["secret"]
        )
        XCTAssertThrowsError(try OCRControlConfig(rules: [duplicate, duplicate]).validate())

        let badRegex = OCRClassificationRule(
            ruleId: "regex",
            name: "Broken",
            classification: "Secret",
            type: .regularExpression,
            pattern: "("
        )
        XCTAssertThrowsError(try OCRControlConfig(rules: [badRegex]).validate())
    }

    func testRepositoryPolicySamplesStrictlyDecode() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()

        for name in ["sample_policy.json", "audit_policy.json"] {
            let data = try Data(contentsOf: root.appendingPathComponent("Config/\(name)"))
            XCTAssertNoThrow(try VeloxPolicy.decodeStrict(from: data), name)
        }
    }
}
