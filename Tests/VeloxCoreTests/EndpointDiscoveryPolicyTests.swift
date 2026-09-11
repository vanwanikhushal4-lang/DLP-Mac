import XCTest
@testable import VeloxCore

final class EndpointDiscoveryPolicyTests: XCTestCase {
    func testOlderPolicyDefaultsDiscoveryToDisabled() throws {
        let json = """
        {
          "policyVersion": 1,
          "applicationControl": { "mode": "audit-only" }
        }
        """
        let policy = try VeloxPolicy.decodeStrict(from: Data(json.utf8))
        XCTAssertEqual(policy.endpointDiscoveryControl, EndpointDiscoveryControlConfig())
        XCTAssertEqual(policy.endpointDiscoveryControl.mode, .disabled)
    }

    func testStrictDecoderAcceptsValidDiscoveryConfiguration() throws {
        let json = """
        {
          "policyVersion": 7,
          "applicationControl": { "mode": "audit-only" },
          "endpointDiscoveryControl": {
            "mode": "enforce",
            "scheduleIntervalMinutes": 60,
            "includeLocalHome": true,
            "includeMountedVolumes": true,
            "includeMountedShares": true,
            "tagClassifiedFiles": true,
            "maxFilesPerScan": 2500
          }
        }
        """
        let policy = try VeloxPolicy.decodeStrict(from: Data(json.utf8))
        XCTAssertEqual(policy.endpointDiscoveryControl.mode, .enforce)
        XCTAssertEqual(policy.endpointDiscoveryControl.scheduleIntervalMinutes, 60)
        XCTAssertEqual(policy.endpointDiscoveryControl.maxFilesPerScan, 2500)
        XCTAssertTrue(policy.endpointDiscoveryControl.tagClassifiedFiles)
    }

    func testDiscoveryRejectsUnsafeScheduleAndEmptyCoverage() {
        XCTAssertThrowsError(try EndpointDiscoveryControlConfig(
            mode: .auditOnly,
            scheduleIntervalMinutes: 5
        ).validate())

        XCTAssertThrowsError(try EndpointDiscoveryControlConfig(
            mode: .auditOnly,
            includeLocalHome: false,
            includeMountedVolumes: false,
            includeMountedShares: false
        ).validate())
    }

    func testStrictDecoderRejectsUnknownDiscoveryProperty() {
        let json = """
        {
          "policyVersion": 1,
          "applicationControl": { "mode": "audit-only" },
          "endpointDiscoveryControl": {
            "mode": "audit-only",
            "unexpected": true
          }
        }
        """
        XCTAssertThrowsError(try VeloxPolicy.decodeStrict(from: Data(json.utf8))) { error in
            guard case PolicyValidationError.unknownProperty = error else {
                XCTFail("Expected unknownProperty, got \(error)")
                return
            }
        }
    }
}
