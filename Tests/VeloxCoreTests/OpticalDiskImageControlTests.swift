import EndpointSecurity
import XCTest
@testable import VeloxCore

final class OpticalDiskImageControlTests: XCTestCase {
    private let appleMountProcess = ProcessContext(
        pid: 321,
        parentPid: 1,
        uid: 0,
        signingId: "com.apple.diskarbitrationd",
        isPlatformBinary: true,
        executablePath: "/usr/libexec/diskarbitrationd"
    )

    func testVirtualDiskImageIsDeniedInEnforceMode() {
        let engine = makeEngine(
            OpticalDiskImageControlConfig(
                mode: .enforce,
                blockDiskImages: true,
                blockOpticalMedia: false
            )
        )

        let decision = engine.evaluateOpticalDiskImageMount(
            process: appleMountProcess,
            mountFrom: "/dev/disk8s1",
            mountPoint: "/Volumes/Installer",
            fsType: "apfs",
            disposition: ES_MOUNT_DISPOSITION_VIRTUAL
        )

        XCTAssertFalse(decision.shouldAllowMount)
        XCTAssertTrue(decision.isCandidate)
        XCTAssertEqual(decision.decisionString, "blocked")
        XCTAssertEqual(decision.mountKind, .diskImage)
        XCTAssertEqual(decision.matchingRuleId, "optical-block-disk-image")
    }

    func testPhysicalOpticalFilesystemIsDeniedInEnforceMode() {
        let engine = makeEngine(
            OpticalDiskImageControlConfig(
                mode: .enforce,
                blockDiskImages: false,
                blockOpticalMedia: true
            )
        )

        let decision = engine.evaluateOpticalDiskImageMount(
            process: appleMountProcess,
            mountFrom: "/dev/disk9",
            mountPoint: "/Volumes/ARCHIVE_DVD",
            fsType: "UDF",
            disposition: ES_MOUNT_DISPOSITION_EXTERNAL
        )

        XCTAssertFalse(decision.shouldAllowMount)
        XCTAssertEqual(decision.mountKind, .opticalMedia)
        XCTAssertEqual(decision.matchingRuleId, "optical-block-media")
    }

    func testAuditOnlyReportsButAllowsCoveredMount() {
        let engine = makeEngine(OpticalDiskImageControlConfig(mode: .auditOnly))

        let decision = engine.evaluateOpticalDiskImageMount(
            process: appleMountProcess,
            mountFrom: "/dev/disk8s1",
            mountPoint: "/Volumes/Installer",
            fsType: "hfs",
            disposition: ES_MOUNT_DISPOSITION_VIRTUAL
        )

        XCTAssertTrue(decision.shouldAllowMount)
        XCTAssertTrue(decision.isCandidate)
        XCTAssertEqual(decision.decisionString, "would-block")
    }

    func testInternalNetworkAndNullfsMountsAreNeverOpticalCandidates() {
        let engine = makeEngine(OpticalDiskImageControlConfig(mode: .enforce))

        for disposition in [
            ES_MOUNT_DISPOSITION_INTERNAL,
            ES_MOUNT_DISPOSITION_NETWORK,
            ES_MOUNT_DISPOSITION_NULLFS,
        ] {
            let decision = engine.evaluateOpticalDiskImageMount(
                process: appleMountProcess,
                mountFrom: "/dev/disk1s1",
                mountPoint: "/Volumes/System",
                fsType: "udf",
                disposition: disposition
            )
            XCTAssertTrue(decision.shouldAllowMount)
            XCTAssertFalse(decision.isCandidate)
        }
    }

    func testRouteFlagsAreIndependent() {
        let diskImagesAllowed = makeEngine(
            OpticalDiskImageControlConfig(
                mode: .enforce,
                blockDiskImages: false,
                blockOpticalMedia: true
            )
        ).evaluateOpticalDiskImageMount(
            process: appleMountProcess,
            mountFrom: "/dev/disk8s1",
            mountPoint: "/Volumes/Installer",
            fsType: "apfs",
            disposition: ES_MOUNT_DISPOSITION_VIRTUAL
        )
        XCTAssertTrue(diskImagesAllowed.shouldAllowMount)
        XCTAssertFalse(diskImagesAllowed.isCandidate)

        let opticalAllowed = makeEngine(
            OpticalDiskImageControlConfig(
                mode: .enforce,
                blockDiskImages: true,
                blockOpticalMedia: false
            )
        ).evaluateOpticalDiskImageMount(
            process: appleMountProcess,
            mountFrom: "/dev/disk9",
            mountPoint: "/Volumes/ARCHIVE_DVD",
            fsType: "udf",
            disposition: ES_MOUNT_DISPOSITION_EXTERNAL
        )
        XCTAssertTrue(opticalAllowed.shouldAllowMount)
        XCTAssertFalse(opticalAllowed.isCandidate)
    }

    func testManagedVeloxContainerMountIsExempt() {
        let engine = makeEngine(OpticalDiskImageControlConfig(mode: .enforce))
        let decision = engine.evaluateOpticalDiskImageMount(
            process: appleMountProcess,
            mountFrom: "/dev/disk10s1",
            mountPoint: "/Volumes/Velox Secure USB",
            fsType: "apfs",
            disposition: ES_MOUNT_DISPOSITION_VIRTUAL,
            isManagedVeloxContainerMount: true
        )

        XCTAssertTrue(decision.shouldAllowMount)
        XCTAssertFalse(decision.isCandidate)
    }

    func testManagedAllowanceRequiresActiveTokenTrustedAppleProcessAndExactName() {
        let allowance = ManagedVirtualMountAllowance()
        let token = allowance.begin(baseVolumeName: "Velox Secure USB")
        defer { allowance.end(token) }

        XCTAssertTrue(allowance.allows(
            process: appleMountProcess,
            mountPoint: "/Volumes/Velox Secure USB"
        ))
        XCTAssertTrue(allowance.allows(
            process: appleMountProcess,
            mountPoint: "/Volumes/Velox Secure USB 2"
        ))
        XCTAssertFalse(allowance.allows(
            process: appleMountProcess,
            mountPoint: "/Volumes/Velox Secure USB Backup"
        ))

        let spoofed = ProcessContext(
            pid: 999,
            uid: 501,
            signingId: "com.apple.diskarbitrationd",
            isPlatformBinary: false,
            executablePath: "/tmp/diskarbitrationd"
        )
        XCTAssertFalse(allowance.allows(
            process: spoofed,
            mountPoint: "/Volumes/Velox Secure USB"
        ))

        allowance.end(token)
        XCTAssertFalse(allowance.allows(
            process: appleMountProcess,
            mountPoint: "/Volumes/Velox Secure USB"
        ))
    }

    func testStrictPolicyRejectsUnknownKeysAndActiveEmptyScope() throws {
        let unknownKeyJSON = """
        {
          "policyVersion": 41,
          "applicationControl": { "mode": "disabled" },
          "opticalDiskImageControl": {
            "mode": "enforce",
            "blockDiskImages": true,
            "blockOpticalMedia": true,
            "allowUntrustedMounts": true
          }
        }
        """
        XCTAssertThrowsError(
            try VeloxPolicy.decodeStrict(from: Data(unknownKeyJSON.utf8))
        ) { error in
            guard case PolicyValidationError.unknownProperty = error else {
                return XCTFail("Expected unknownProperty, got \(error)")
            }
        }

        let emptyScopeJSON = """
        {
          "policyVersion": 42,
          "applicationControl": { "mode": "disabled" },
          "opticalDiskImageControl": {
            "mode": "enforce",
            "blockDiskImages": false,
            "blockOpticalMedia": false
          }
        }
        """
        XCTAssertThrowsError(
            try VeloxPolicy.decodeStrict(from: Data(emptyScopeJSON.utf8))
        ) { error in
            guard case PolicyValidationError.invalidCriterion = error else {
                return XCTFail("Expected invalidCriterion, got \(error)")
            }
        }
    }

    func testLegacyPolicyDefaultsToSafeDisabledConfiguration() throws {
        let json = """
        {
          "policyVersion": 43,
          "applicationControl": { "mode": "disabled" }
        }
        """
        let policy = try VeloxPolicy.decodeStrict(from: Data(json.utf8))
        XCTAssertEqual(policy.opticalDiskImageControl.mode, .disabled)
        XCTAssertTrue(policy.opticalDiskImageControl.blockDiskImages)
        XCTAssertTrue(policy.opticalDiskImageControl.blockOpticalMedia)
    }

    private func makeEngine(_ config: OpticalDiskImageControlConfig) -> PolicyEngine {
        PolicyEngine(
            policy: VeloxPolicy(
                policyVersion: 40,
                applicationControl: ApplicationControlConfig(mode: .disabled),
                opticalDiskImageControl: config
            )
        )
    }
}
