import Darwin
import Foundation
import XCTest
@testable import VeloxCore

final class NativeEgressNetworkHoldStoreTests: XCTestCase {
    private func process() -> ProcessContext {
        ProcessContext(
            pid: 4242,
            parentPid: 1,
            uid: 501,
            signingId: "net.whatsapp.WhatsApp",
            teamId: "57T9237FN3",
            isPlatformBinary: false,
            cdhash: nil,
            executablePath: "/Applications/WhatsApp.app/Contents/MacOS/WhatsApp"
        )
    }

    private func makeStore() throws -> (NativeEgressNetworkHoldStore, URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("velox-native-hold-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let file = directory.appendingPathComponent("holds.json")
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        return (NativeEgressNetworkHoldStore(path: file.path), file)
    }

    private func waitForHold(
        in store: NativeEgressNetworkHoldStore,
        timeout: TimeInterval = 2
    ) -> NativeEgressNetworkHold? {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let hold = store.activeHold(
                signingId: "net.whatsapp.WhatsApp.ServiceExtension",
                teamId: "57T9237FN3"
            ) {
                return hold
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
        return nil
    }

    func testPendingHoldCoversAnotherConfiguredClientFromSameTeam() throws {
        let (store, file) = try makeStore()
        store.beginHoldAsync(
            filePath: "/Users/alice/Downloads/id.png",
            process: process(),
            policyVersion: 7,
            classifications: []
        )

        let hold = waitForHold(in: store)
        XCTAssertEqual(hold?.status, .pendingClassification)
        XCTAssertEqual(hold?.originSigningId, "net.whatsapp.WhatsApp")

        var info = stat()
        XCTAssertEqual(lstat(file.path, &info), 0)
        XCTAssertEqual(info.st_mode & mode_t(0o777), mode_t(0o600))
    }

    func testCleanClassificationReleasesPendingHold() throws {
        let (store, _) = try makeStore()
        let path = "/Users/alice/Downloads/clean.png"
        store.beginHoldAsync(
            filePath: path,
            process: process(),
            policyVersion: 8,
            classifications: []
        )
        XCTAssertNotNil(waitForHold(in: store))

        store.resolveClassification(filePath: path, classifications: [], policyVersion: 8)

        XCTAssertNil(store.activeHold(
            signingId: "net.whatsapp.WhatsApp",
            teamId: "57T9237FN3"
        ))
    }

    func testSensitiveClassificationKeepsBlockedHold() throws {
        let (store, _) = try makeStore()
        let path = "/Users/alice/Downloads/aadhaar.png"
        store.beginHoldAsync(
            filePath: path,
            process: process(),
            policyVersion: 9,
            classifications: []
        )
        XCTAssertNotNil(waitForHold(in: store))

        store.resolveClassification(
            filePath: path,
            classifications: ["Indian Identity Data"],
            policyVersion: 9
        )

        let hold = store.activeHold(
            signingId: "net.whatsapp.WhatsApp",
            teamId: "57T9237FN3"
        )
        XCTAssertEqual(hold?.status, .blockedContent)
        XCTAssertEqual(hold?.classifications, ["Indian Identity Data"])
    }

    func testVerifiedRemediationShortensOnlyTheResolvedProtectedHold() throws {
        let (store, _) = try makeStore()
        let path = "/Users/alice/Downloads/aadhaar.png"
        store.beginHoldAsync(
            filePath: path,
            process: process(),
            policyVersion: 10,
            classifications: []
        )
        XCTAssertNotNil(waitForHold(in: store))

        let resolved = store.resolveClassification(
            filePath: path,
            classifications: ["Indian Identity Data"],
            policyVersion: 10
        )
        let hold = try XCTUnwrap(resolved.first)
        let remediationTime = NativeEgressNetworkHoldStore.nowMillis()
        store.markRemediated(
            holdIds: [hold.holdId],
            nowMillis: remediationTime
        )

        XCTAssertNotNil(store.activeHold(
            signingId: "net.whatsapp.WhatsApp",
            teamId: "57T9237FN3",
            nowMillis: remediationTime + NativeEgressNetworkHoldStore.remediatedLifetimeMillis - 1
        ))
        XCTAssertNil(store.activeHold(
            signingId: "net.whatsapp.WhatsApp",
            teamId: "57T9237FN3",
            nowMillis: remediationTime + NativeEgressNetworkHoldStore.remediatedLifetimeMillis + 1
        ))
    }
}
