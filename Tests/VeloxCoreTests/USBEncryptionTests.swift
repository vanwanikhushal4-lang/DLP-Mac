import Darwin
import XCTest
@testable import VeloxCore

final class USBEncryptionTests: XCTestCase {
    private let volume = ManagedUSBEncryptionVolume(
        identifier: "disk7s1",
        volumeName: "CLIENT_USB",
        mountPath: "/Volumes/CLIENT_USB",
        containerBackingPath: "/Volumes/CLIENT_USB/.velox/VeloxSecure.sparsebundle"
    )

    func testDirectPlaintextWriteIsBlockedInEnforceMode() {
        let controller = configuredController(mode: .enforce)
        let decision = controller.evaluateOpen(
            process: finder,
            filePath: "/Volumes/CLIENT_USB/Confidential.pdf",
            requestedFlags: UInt32(O_WRONLY | O_CREAT)
        )

        XCTAssertEqual(decision?.decisionString, "blocked")
        XCTAssertEqual(decision?.shouldAllow, false)
        XCTAssertEqual(decision?.volumeName, "CLIENT_USB")
    }

    func testReadFromOuterVolumeIsNotBlocked() {
        let controller = configuredController(mode: .enforce)
        XCTAssertNil(
            controller.evaluateOpen(
                process: finder,
                filePath: "/Volumes/CLIENT_USB/existing.txt",
                requestedFlags: UInt32(O_RDONLY)
            )
        )
    }

    func testAuditModeAllowsAndReportsPlaintextWrite() {
        let controller = configuredController(mode: .auditOnly)
        let decision = controller.evaluateMutation(
            process: finder,
            destinationPath: "/Volumes/CLIENT_USB/report.csv",
            operation: .create
        )

        XCTAssertEqual(decision?.decisionString, "would-encrypt")
        XCTAssertEqual(decision?.shouldAllow, true)
    }

    func testDisabledModeDoesNotTreatOuterVolumeAsCandidate() {
        let controller = configuredController(mode: .disabled)
        XCTAssertNil(
            controller.evaluateMutation(
                process: finder,
                destinationPath: "/Volumes/CLIENT_USB/report.csv",
                operation: .copyFile
            )
        )
    }

    func testTrustedAppleDiskImageWriterCanUpdateBackingStore() {
        let controller = configuredController(mode: .enforce)
        let helper = ProcessContext(
            pid: 100,
            parentPid: 1,
            uid: 0,
            signingId: "com.apple.diskimages-helper",
            teamId: nil,
            isPlatformBinary: true,
            cdhash: nil,
            executablePath: "/System/Library/PrivateFrameworks/DiskImages.framework/Versions/A/Resources/diskimages-helper"
        )

        XCTAssertNil(
            controller.evaluateOpen(
                process: helper,
                filePath: "/Volumes/CLIENT_USB/.velox/VeloxSecure.sparsebundle/bands/0",
                requestedFlags: UInt32(O_RDWR)
            )
        )
    }

    func testUntrustedProcessCannotTamperWithBackingStore() {
        let controller = configuredController(mode: .enforce)
        let decision = controller.evaluateMutation(
            process: finder,
            destinationPath: "/Volumes/CLIENT_USB/.velox/VeloxSecure.sparsebundle/token",
            operation: .create
        )
        XCTAssertEqual(decision?.shouldAllow, false)
    }

    func testAuthenticatedVeloxESClientCanCreateContainerIdentity() {
        let controller = configuredController(mode: .enforce)
        let extensionProcess = ProcessContext(
            pid: 88,
            parentPid: 1,
            uid: 0,
            signingId: "co.velox.macdlp.endpointsecurity",
            teamId: "L7US4BH7Q2",
            isPlatformBinary: false,
            cdhash: nil,
            executablePath: "/Library/SystemExtensions/Velox/co.velox.macdlp.endpointsecurity",
            isESClient: true
        )

        XCTAssertNil(
            controller.evaluateMutation(
                process: extensionProcess,
                destinationPath: "/Volumes/CLIENT_USB/.velox/container-id",
                operation: .create
            )
        )
    }

    func testMountPathBoundaryDoesNotMatchSimilarVolumeName() {
        let controller = configuredController(mode: .enforce)
        XCTAssertNil(
            controller.evaluateMutation(
                process: finder,
                destinationPath: "/Volumes/CLIENT_USB_BACKUP/report.csv",
                operation: .create
            )
        )
    }

    func testDiskutilExternalVolumeParserHandlesNestedPartitions() throws {
        let fixture: [String: Any] = [
            "AllDisksAndPartitions": [[
                "DeviceIdentifier": "disk7",
                "Size": 64_000_000_000,
                "Partitions": [[
                    "DeviceIdentifier": "disk7s1",
                    "VolumeName": "CLIENT_USB",
                    "MountPoint": "/Volumes/CLIENT_USB",
                    "Size": 63_999_000_000
                ]]
            ]]
        ]
        let data = try PropertyListSerialization.data(
            fromPropertyList: fixture,
            format: .xml,
            options: 0
        )

        XCTAssertEqual(
            try ExternalUSBVolumeParser.parseDiskutilListPlist(data),
            [
                ExternalUSBVolumeDescriptor(
                    deviceIdentifier: "disk7s1",
                    volumeName: "CLIENT_USB",
                    mountPath: "/Volumes/CLIENT_USB",
                    sizeBytes: 63_999_000_000
                )
            ]
        )
    }

    func testUSBEncryptionPolicyRejectsContradictoryAndUnsafeSettings() throws {
        let contradictory = """
        {
          "policyVersion": 8,
          "applicationControl": { "mode": "enforce" },
          "usbStorageControl": {
            "mode": "enforce",
            "blockExternalStorage": true,
            "encryptionMode": "enforce",
            "containerSizePercent": 90
          }
        }
        """
        XCTAssertThrowsError(try VeloxPolicy.decodeStrict(from: Data(contradictory.utf8)))

        let invalidSize = """
        {
          "policyVersion": 9,
          "applicationControl": { "mode": "enforce" },
          "usbStorageControl": {
            "mode": "disabled",
            "blockExternalStorage": true,
            "encryptionMode": "enforce",
            "containerSizePercent": 100
          }
        }
        """
        XCTAssertThrowsError(try VeloxPolicy.decodeStrict(from: Data(invalidSize.utf8)))
    }

    private func configuredController(mode: PolicyMode) -> USBEncryptionAccessController {
        let controller = USBEncryptionAccessController()
        controller.update(mode: mode, policyVersion: 7, volumes: [volume])
        return controller
    }

    private var finder: ProcessContext {
        ProcessContext(
            pid: 501,
            parentPid: 1,
            uid: 501,
            signingId: "com.apple.finder",
            teamId: nil,
            isPlatformBinary: true,
            cdhash: nil,
            executablePath: "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"
        )
    }
}
