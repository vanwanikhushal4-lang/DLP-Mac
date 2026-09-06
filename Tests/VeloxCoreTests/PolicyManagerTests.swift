import XCTest
import os
@testable import VeloxCore

final class PolicyManagerTests: XCTestCase {
    var tempDirectory: URL!
    var policyURL: URL!
    var logURL: URL!

    override func setUp() {
        super.setUp()
        tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try! FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        policyURL = tempDirectory.appendingPathComponent("policy.json")
        logURL = tempDirectory.appendingPathComponent("events.jsonl")
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempDirectory)
        super.tearDown()
    }

    func testLoadValidPolicy() {
        let validJSON = """
        {
          "policyVersion": 1,
          "applicationControl": {
            "mode": "enforce",
            "blockedApplications": [
              { "ruleId": "block-calculator", "signingId": "com.apple.calculator" }
            ]
          }
        }
        """
        try! validJSON.data(using: .utf8)!.write(to: policyURL)

        let manager = PolicyManager(policyPath: policyURL.path)
        let policy = manager.policyEngine.currentPolicy()
        XCTAssertEqual(policy.policyVersion, 1)
        XCTAssertEqual(policy.applicationControl.mode, .enforce)
        XCTAssertEqual(policy.applicationControl.blockedApplications.count, 1)
        XCTAssertEqual(policy.applicationControl.blockedApplications[0].signingId, "com.apple.calculator")
        XCTAssertEqual(policy.webUploadControl.mode, .disabled, "Legacy policies must default web uploads to disabled")
        XCTAssertEqual(policy.usbStorageControl.encryptionMode, .disabled, "Legacy policies must not require a container")
        XCTAssertEqual(policy.usbStorageControl.containerSizePercent, 90)
        XCTAssertEqual(policy.printerControl.mode, .disabled, "Legacy policies must default printer control to disabled")
    }

    func testLoadWebUploadPolicyAndRejectUnknownProperties() throws {
        let validJSON = """
        {
          "policyVersion": 12,
          "applicationControl": { "mode": "enforce" },
          "webUploadControl": {
            "mode": "audit-only",
            "protectedDirectoryNames": ["Desktop", "Documents"]
          }
        }
        """
        let policy = try VeloxPolicy.decodeStrict(from: validJSON.data(using: .utf8)!)
        XCTAssertEqual(policy.webUploadControl.mode, .auditOnly)
        XCTAssertEqual(policy.webUploadControl.protectedDirectoryNames, ["Desktop", "Documents"])

        let invalidJSON = """
        {
          "policyVersion": 12,
          "applicationControl": { "mode": "enforce" },
          "webUploadControl": {
            "mode": "enforce",
            "bypassEverything": true
          }
        }
        """
        XCTAssertThrowsError(try VeloxPolicy.decodeStrict(from: invalidJSON.data(using: .utf8)!)) { error in
            guard case PolicyValidationError.unknownProperty = error else {
                XCTFail("Expected unknownProperty, got \(error)")
                return
            }
        }
    }

    func testRejectUnknownProperties() {
        let invalidJSON = """
        {
          "policyVersion": 1,
          "applicationControl": {
            "mode": "enforce",
            "blockedApplications": []
          },
          "misspelledProperty": "surprise"
        }
        """
        try! invalidJSON.data(using: .utf8)!.write(to: policyURL)

        let manager = PolicyManager(policyPath: policyURL.path)
        // Fallback default is retained
        XCTAssertEqual(manager.policyEngine.currentPolicy().policyVersion, 1)

        XCTAssertThrowsError(try VeloxPolicy.decodeStrict(from: invalidJSON.data(using: .utf8)!)) { error in
            guard case PolicyValidationError.unknownProperty(let msg) = error else {
                XCTFail("Expected unknownProperty error, got \(error)")
                return
            }
            XCTAssertTrue(msg.contains("misspelledProperty"))
        }
    }

    func testRejectEmptyMatchingValues() {
        let emptySigningIdJSON = """
        {
          "policyVersion": 1,
          "applicationControl": {
            "mode": "enforce",
            "blockedApplications": [
              { "ruleId": "empty-rule", "signingId": "   " }
            ]
          }
        }
        """
        XCTAssertThrowsError(try VeloxPolicy.decodeStrict(from: emptySigningIdJSON.data(using: .utf8)!)) { error in
            guard case PolicyValidationError.emptyCriterion = error else {
                XCTFail("Expected emptyCriterion error, got \(error)")
                return
            }
        }
    }

    func testRejectUnsafePathPrefix() {
        let rootPrefixJSON = """
        {
          "policyVersion": 1,
          "applicationControl": {
            "mode": "enforce",
            "blockedApplications": [
              { "ruleId": "unsafe-root", "executablePathPrefix": "/" }
            ]
          }
        }
        """
        XCTAssertThrowsError(try VeloxPolicy.decodeStrict(from: rootPrefixJSON.data(using: .utf8)!)) { error in
            guard case PolicyValidationError.unsafePathPrefix = error else {
                XCTFail("Expected unsafePathPrefix error, got \(error)")
                return
            }
        }
    }

    func testRejectDuplicateRuleIds() {
        let duplicateJSON = """
        {
          "policyVersion": 1,
          "applicationControl": {
            "mode": "enforce",
            "blockedApplications": [
              { "ruleId": "duplicate-id", "signingId": "com.apple.calculator" },
              { "ruleId": "duplicate-id", "signingId": "com.apple.TextEdit" }
            ]
          }
        }
        """
        XCTAssertThrowsError(try VeloxPolicy.decodeStrict(from: duplicateJSON.data(using: .utf8)!)) { error in
            guard case PolicyValidationError.duplicateRuleId = error else {
                XCTFail("Expected duplicateRuleId error, got \(error)")
                return
            }
        }
    }

    func testRejectVersionRollback() {
        let initialJSON = """
        {
          "policyVersion": 3,
          "applicationControl": {
            "mode": "enforce",
            "blockedApplications": [
              { "ruleId": "block-calculator", "signingId": "com.apple.calculator" }
            ]
          }
        }
        """
        try! initialJSON.data(using: .utf8)!.write(to: policyURL)
        let manager = PolicyManager(policyPath: policyURL.path)
        XCTAssertEqual(manager.policyEngine.currentPolicy().policyVersion, 3)

        // Attempt rollback to version 2
        let rollbackJSON = """
        {
          "policyVersion": 2,
          "applicationControl": {
            "mode": "enforce",
            "blockedApplications": []
          }
        }
        """
        try! rollbackJSON.data(using: .utf8)!.write(to: policyURL)
        let reloadResult = manager.reloadPolicyFromDisk()
        XCTAssertFalse(reloadResult, "Rollback to lower version must be rejected")
        XCTAssertEqual(manager.policyEngine.currentPolicy().policyVersion, 3)
    }

    func testMalformedPolicyEmitsStructuredJSONLErrorLog() throws {
        let initialJSON = """
        {
          "policyVersion": 1,
          "applicationControl": {
            "mode": "enforce",
            "blockedApplications": [
              { "ruleId": "block-calculator", "signingId": "com.apple.calculator" }
            ]
          }
        }
        """
        try! initialJSON.data(using: .utf8)!.write(to: policyURL)
        let logger = EventLogger(logFilePath: logURL.path)
        let manager = PolicyManager(policyPath: policyURL.path, logger: logger)

        // Write corrupt JSON
        try! "{ corrupt: json missing bracket".data(using: .utf8)!.write(to: policyURL)
        let reloadResult = manager.reloadPolicyFromDisk()
        XCTAssertFalse(reloadResult)
        logger.flushSync()

        let content = try String(contentsOf: logURL, encoding: .utf8)
        let lines = content.components(separatedBy: "\n").filter { !$0.isEmpty }
        XCTAssertGreaterThanOrEqual(lines.count, 1)

        let parsed = try JSONSerialization.jsonObject(with: lines[0].data(using: .utf8)!) as! [String: Any]
        XCTAssertEqual(parsed["module"] as? String, "policy-manager")
        XCTAssertEqual(parsed["action"] as? String, "policy-error")
        XCTAssertEqual(parsed["decision"] as? String, "retained-last-valid")
        XCTAssertEqual(parsed["policyVersion"] as? Int, 1)
    }

    func testApplyPolicyPersistsAndActivatesSynchronously() throws {
        let manager = PolicyManager(policyPath: policyURL.path)
        let updated = VeloxPolicy(
            policyVersion: 2,
            applicationControl: ApplicationControlConfig(
                mode: .enforce,
                blockedApplications: [
                    ApplicationRule(ruleId: "console-test", signingId: "com.apple.TextEdit")
                ]
            )
        )

        try manager.applyPolicy(updated, persistToDisk: true)

        XCTAssertEqual(manager.policyEngine.currentPolicy(), updated)
        XCTAssertEqual(PolicyManager.loadPolicyFromFile(at: policyURL.path), updated)
    }

    func testApplyPolicyRejectsRollbackWithoutOverwritingDisk() throws {
        let active = VeloxPolicy(
            policyVersion: 4,
            applicationControl: ApplicationControlConfig(mode: .enforce)
        )
        let manager = PolicyManager(policyPath: policyURL.path, initialPolicy: active)
        let rollback = VeloxPolicy(
            policyVersion: 3,
            applicationControl: ApplicationControlConfig(mode: .disabled)
        )

        XCTAssertThrowsError(try manager.applyPolicy(rollback, persistToDisk: true))
        XCTAssertEqual(manager.policyEngine.currentPolicy(), active)
        XCTAssertFalse(FileManager.default.fileExists(atPath: policyURL.path))
    }

    func testMonitoringSurvivesConsecutiveAtomicPolicyReplacements() throws {
        let initial = VeloxPolicy(
            policyVersion: 1,
            applicationControl: ApplicationControlConfig(mode: .enforce)
        )
        try JSONEncoder().encode(initial).write(to: policyURL)

        let manager = PolicyManager(policyPath: policyURL.path)
        let versionTwoReloaded = expectation(description: "version two reloaded")
        manager.onPolicyReloaded = { policy in
            if policy.policyVersion == 2 { versionTwoReloaded.fulfill() }
        }
        manager.startMonitoring()

        let versionTwo = VeloxPolicy(
            policyVersion: 2,
            applicationControl: ApplicationControlConfig(mode: .auditOnly)
        )
        try JSONEncoder().encode(versionTwo).write(to: policyURL, options: .atomic)
        wait(for: [versionTwoReloaded], timeout: 3)

        let versionThreeReloaded = expectation(description: "version three reloaded")
        manager.onPolicyReloaded = { policy in
            if policy.policyVersion == 3 { versionThreeReloaded.fulfill() }
        }
        let versionThree = VeloxPolicy(
            policyVersion: 3,
            applicationControl: ApplicationControlConfig(mode: .disabled)
        )
        try JSONEncoder().encode(versionThree).write(to: policyURL, options: .atomic)
        wait(for: [versionThreeReloaded], timeout: 3)

        XCTAssertEqual(manager.policyEngine.currentPolicy(), versionThree)
        manager.stopMonitoring()
    }
}
