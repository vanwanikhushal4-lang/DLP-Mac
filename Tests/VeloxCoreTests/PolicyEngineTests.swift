import XCTest
import Darwin
import EndpointSecurity
@testable import VeloxCore

final class PolicyEngineTests: XCTestCase {

    func testBlockCalculatorInEnforceMode() {
        let rule = ApplicationRule(ruleId: "block-calculator", signingId: "com.apple.calculator")
        let config = ApplicationControlConfig(mode: .enforce, blockedApplications: [rule])
        let policy = VeloxPolicy(policyVersion: 1, applicationControl: config)
        let engine = PolicyEngine(policy: policy)

        let calcProcess = ProcessContext(
            pid: 1234,
            parentPid: 1,
            uid: 501,
            signingId: "com.apple.calculator",
            teamId: nil,
            isPlatformBinary: true,
            cdhash: "04e68ce8e9f4131664beb569a6b7f92763f8a28f",
            executablePath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"
        )

        let decision = engine.evaluate(process: calcProcess)
        XCTAssertEqual(decision.decisionString, "blocked")
        XCTAssertFalse(decision.shouldAllowExecution)
        XCTAssertEqual(decision.matchingRuleId, "block-calculator")
        XCTAssertEqual(decision.policyVersion, 1)
    }

    func testCalculatorInAuditOnlyMode() {
        let rule = ApplicationRule(ruleId: "block-calculator", signingId: "com.apple.calculator")
        let config = ApplicationControlConfig(mode: .auditOnly, blockedApplications: [rule])
        let policy = VeloxPolicy(policyVersion: 2, applicationControl: config)
        let engine = PolicyEngine(policy: policy)

        let calcProcess = ProcessContext(
            pid: 1235,
            parentPid: 1,
            uid: 501,
            signingId: "com.apple.calculator",
            teamId: nil,
            isPlatformBinary: true,
            cdhash: "04e68ce8e9f4131664beb569a6b7f92763f8a28f",
            executablePath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"
        )

        let decision = engine.evaluate(process: calcProcess)
        XCTAssertEqual(decision.decisionString, "would-block")
        XCTAssertTrue(decision.shouldAllowExecution, "Audit-only mode must allow process execution")
        XCTAssertEqual(decision.matchingRuleId, "block-calculator")
        XCTAssertEqual(decision.policyVersion, 2)
    }

    func testRenamedOrCopiedBinaryCannotBypassRule() {
        let rule = ApplicationRule(ruleId: "block-calculator", signingId: "com.apple.calculator")
        let config = ApplicationControlConfig(mode: .enforce, blockedApplications: [rule])
        let policy = VeloxPolicy(policyVersion: 1, applicationControl: config)
        let engine = PolicyEngine(policy: policy)

        // Copied to /tmp and renamed to harmless_math
        let copiedProcess = ProcessContext(
            pid: 1236,
            parentPid: 500,
            uid: 501,
            signingId: "com.apple.calculator", // Signing ID remains intact!
            teamId: nil,
            isPlatformBinary: true,
            cdhash: "04e68ce8e9f4131664beb569a6b7f92763f8a28f",
            executablePath: "/private/tmp/harmless_math"
        )

        let decision = engine.evaluate(process: copiedProcess)
        XCTAssertEqual(decision.decisionString, "blocked")
        XCTAssertFalse(decision.shouldAllowExecution)
        XCTAssertEqual(decision.matchingRuleId, "block-calculator")
    }

    func testUnrelatedApplicationLaunchesNormally() {
        let rule = ApplicationRule(ruleId: "block-calculator", signingId: "com.apple.calculator")
        let config = ApplicationControlConfig(mode: .enforce, blockedApplications: [rule])
        let policy = VeloxPolicy(policyVersion: 1, applicationControl: config)
        let engine = PolicyEngine(policy: policy)

        let terminalProcess = ProcessContext(
            pid: 1237,
            parentPid: 1,
            uid: 501,
            signingId: "com.apple.Terminal",
            teamId: nil,
            isPlatformBinary: true,
            cdhash: "11223344556677889900aabbccddeeff00112233",
            executablePath: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"
        )

        let decision = engine.evaluate(process: terminalProcess)
        XCTAssertEqual(decision.decisionString, "allowed")
        XCTAssertTrue(decision.shouldAllowExecution)
        XCTAssertNil(decision.matchingRuleId)
    }

    func testAllowedRuleOverridesBlockRule() {
        let blockRule = ApplicationRule(ruleId: "block-all-calc", signingId: "com.apple.calculator")
        let allowRule = ApplicationRule(
            ruleId: "allow-system-calc",
            signingId: "com.apple.calculator",
            executablePath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"
        )

        let config = ApplicationControlConfig(
            mode: .enforce,
            blockedApplications: [blockRule],
            allowedApplications: [allowRule]
        )
        let policy = VeloxPolicy(policyVersion: 3, applicationControl: config)
        let engine = PolicyEngine(policy: policy)

        let sysCalc = ProcessContext(
            pid: 1238,
            parentPid: 1,
            uid: 501,
            signingId: "com.apple.calculator",
            teamId: nil,
            isPlatformBinary: true,
            cdhash: "04e68ce8e9f4131664beb569a6b7f92763f8a28f",
            executablePath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"
        )

        let decision = engine.evaluate(process: sysCalc)
        XCTAssertEqual(decision.decisionString, "allowed")
        XCTAssertTrue(decision.shouldAllowExecution)
        XCTAssertEqual(decision.matchingRuleId, "allow-system-calc")
    }

    func testCriticalMacOSProcessesCannotBeBlocked() {
        // Administrator misconfiguration attempts to block all apple binaries
        let broadRule = ApplicationRule(ruleId: "block-apple", isPlatformBinary: true)
        let config = ApplicationControlConfig(mode: .enforce, blockedApplications: [broadRule])
        let policy = VeloxPolicy(policyVersion: 1, applicationControl: config)
        let engine = PolicyEngine(policy: policy)

        let launchdProcess = ProcessContext(
            pid: 1,
            parentPid: 0,
            uid: 0,
            signingId: "com.apple.launchd",
            teamId: nil,
            isPlatformBinary: true,
            cdhash: "0000000000000000000000000000000000000000",
            executablePath: "/sbin/launchd"
        )

        let decision = engine.evaluate(process: launchdProcess)
        XCTAssertEqual(decision.decisionString, "allowed", "launchd must NEVER be blocked")
        XCTAssertTrue(decision.shouldAllowExecution)
        XCTAssertNil(decision.matchingRuleId)

        let windowServer = ProcessContext(
            pid: 200,
            parentPid: 1,
            uid: 88,
            signingId: "com.apple.WindowServer",
            teamId: nil,
            isPlatformBinary: true,
            cdhash: "1111111111111111111111111111111111111111",
            executablePath: "/System/Library/Frameworks/CoreGraphics.framework/WindowServer"
        )

        let wsDecision = engine.evaluate(process: windowServer)
        XCTAssertEqual(wsDecision.decisionString, "allowed", "WindowServer must NEVER be blocked")
        XCTAssertTrue(wsDecision.shouldAllowExecution)
    }

    func testEvaluationPerformanceUnder50Microseconds() {
        let rule = ApplicationRule(ruleId: "block-calculator", signingId: "com.apple.calculator")
        let config = ApplicationControlConfig(mode: .enforce, blockedApplications: [rule])
        let policy = VeloxPolicy(policyVersion: 1, applicationControl: config)
        let engine = PolicyEngine(policy: policy)

        let proc = ProcessContext(
            pid: 1234,
            parentPid: 1,
            uid: 501,
            signingId: "com.apple.calculator",
            teamId: nil,
            isPlatformBinary: true,
            cdhash: "04e68ce8e9f4131664beb569a6b7f92763f8a28f",
            executablePath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"
        )

        // Warm up
        _ = engine.evaluate(process: proc)

        let iterations = 10_000
        let start = DispatchTime.now().uptimeNanoseconds
        for _ in 0..<iterations {
            _ = engine.evaluate(process: proc)
        }
        let end = DispatchTime.now().uptimeNanoseconds
        let totalElapsedNs = end - start
        let averageMicroseconds = Double(totalElapsedNs) / Double(iterations) / 1_000.0

        print("Average in-memory policy evaluation time: \(averageMicroseconds) microseconds")
        XCTAssertLessThan(averageMicroseconds, 50.0, "Evaluation latency must be well under 50 microseconds")
    }

    func testPathPrefixDirectoryBoundarySafety() {
        let rule = ApplicationRule(ruleId: "block-safe-dir", executablePathPrefix: "/Applications/Safe")
        let config = ApplicationControlConfig(mode: .enforce, blockedApplications: [rule])
        let policy = VeloxPolicy(policyVersion: 1, applicationControl: config)
        let engine = PolicyEngine(policy: policy)

        // Exact match -> blocked
        let exactProc = ProcessContext(
            pid: 101, parentPid: 1, uid: 501, signingId: nil, teamId: nil,
            isPlatformBinary: false, cdhash: nil, executablePath: "/Applications/Safe"
        )
        XCTAssertEqual(engine.evaluate(process: exactProc).decisionString, "blocked")

        // Subdirectory child -> blocked
        let childProc = ProcessContext(
            pid: 102, parentPid: 1, uid: 501, signingId: nil, teamId: nil,
            isPlatformBinary: false, cdhash: nil, executablePath: "/Applications/Safe/Helper"
        )
        XCTAssertEqual(engine.evaluate(process: childProc).decisionString, "blocked")

        // Sibling path prefix extension (/Applications/SafeEvil) -> MUST NOT MATCH -> allowed
        let evilProc = ProcessContext(
            pid: 103, parentPid: 1, uid: 501, signingId: nil, teamId: nil,
            isPlatformBinary: false, cdhash: nil, executablePath: "/Applications/SafeEvil"
        )
        XCTAssertEqual(engine.evaluate(process: evilProc).decisionString, "allowed", "Path prefix without slash boundary must not match sibling paths")
    }

    func testInsecureAllowRuleIsRejected() {
        // Allow rule specifying only signingId without cryptographic constraint must be rejected
        let insecureAllow = ApplicationRule(ruleId: "insecure-allow", signingId: "com.spoofable.app")
        let config = ApplicationControlConfig(mode: .enforce, allowedApplications: [insecureAllow])
        let policy = VeloxPolicy(policyVersion: 1, applicationControl: config)

        XCTAssertThrowsError(try policy.validate()) { error in
            guard case PolicyValidationError.insecureAllowRule = error else {
                XCTFail("Expected PolicyValidationError.insecureAllowRule, got: \(error)")
                return
            }
        }
    }

    func testWebUploadEnforcementBlocksBrowserReadFromProtectedFolder() {
        let policy = VeloxPolicy(
            policyVersion: 8,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            webUploadControl: WebUploadControlConfig(mode: .enforce)
        )
        let engine = PolicyEngine(policy: policy)
        let chrome = ProcessContext(
            pid: 400, parentPid: 1, uid: 501,
            signingId: "com.google.Chrome.helper.renderer", teamId: "EQHXZ8M8AV",
            isPlatformBinary: false, cdhash: nil,
            executablePath: "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"
        )

        let decision = engine.evaluateWebUploadOpen(
            process: chrome,
            filePath: "/Users/alice/Documents/customer-list.xlsx",
            requestedFlags: UInt32(FREAD),
            isRegularFile: true
        )

        XCTAssertTrue(decision.isUploadCandidate)
        XCTAssertFalse(decision.shouldAllowOpen)
        XCTAssertEqual(decision.decisionString, "blocked")
        XCTAssertEqual(decision.policyVersion, 8)
    }

    func testWebUploadEnforcementAllowsDownloadWrite() {
        let policy = VeloxPolicy(
            policyVersion: 9,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            webUploadControl: WebUploadControlConfig(mode: .enforce)
        )
        let engine = PolicyEngine(policy: policy)
        let chrome = ProcessContext(
            pid: 401, parentPid: 1, uid: 501,
            signingId: "com.google.Chrome", teamId: "EQHXZ8M8AV",
            isPlatformBinary: false, cdhash: nil,
            executablePath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        )

        let decision = engine.evaluateWebUploadOpen(
            process: chrome,
            filePath: "/Users/alice/Downloads/allowed-download.zip",
            requestedFlags: UInt32(FWRITE),
            isRegularFile: true
        )

        XCTAssertFalse(decision.isUploadCandidate)
        XCTAssertTrue(decision.shouldAllowOpen)
        XCTAssertEqual(decision.decisionString, "allowed")
    }

    func testWebUploadEnforcementAllowsBrowserDownloadFinalization() {
        let policy = VeloxPolicy(
            policyVersion: 9,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            webUploadControl: WebUploadControlConfig(mode: .enforce)
        )
        let engine = PolicyEngine(policy: policy)
        let chrome = ProcessContext(
            pid: 405, parentPid: 1, uid: 501,
            signingId: "com.google.Chrome", teamId: "EQHXZ8M8AV",
            isPlatformBinary: false, cdhash: nil,
            executablePath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        )

        let partialDecision = engine.evaluateWebUploadOpen(
            process: chrome,
            filePath: "/Users/alice/Downloads/file.zip.crdownload",
            requestedFlags: UInt32(FREAD),
            isRegularFile: true
        )
        let finalizationDecision = engine.evaluateWebUploadOpen(
            process: chrome,
            filePath: "/Users/alice/Downloads/file.zip",
            requestedFlags: 32_773,
            isRegularFile: true
        )

        XCTAssertTrue(partialDecision.shouldAllowOpen)
        XCTAssertFalse(partialDecision.isUploadCandidate)
        XCTAssertTrue(finalizationDecision.shouldAllowOpen)
        XCTAssertFalse(finalizationDecision.isUploadCandidate)
    }

    func testWebUploadEnforcementDoesNotBlockBrowserProfilesOrOtherApps() {
        let policy = VeloxPolicy(
            policyVersion: 10,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            webUploadControl: WebUploadControlConfig(mode: .enforce)
        )
        let engine = PolicyEngine(policy: policy)
        let chrome = ProcessContext(
            pid: 402, parentPid: 1, uid: 501,
            signingId: "com.google.Chrome", teamId: "EQHXZ8M8AV",
            isPlatformBinary: false, cdhash: nil,
            executablePath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        )
        let textEdit = ProcessContext(
            pid: 403, parentPid: 1, uid: 501,
            signingId: "com.apple.TextEdit", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit"
        )

        let profileDecision = engine.evaluateWebUploadOpen(
            process: chrome,
            filePath: "/Users/alice/Library/Application Support/Google/Chrome/Default/History",
            requestedFlags: UInt32(FREAD),
            isRegularFile: true
        )
        let otherAppDecision = engine.evaluateWebUploadOpen(
            process: textEdit,
            filePath: "/Users/alice/Documents/report.docx",
            requestedFlags: UInt32(FREAD),
            isRegularFile: true
        )

        XCTAssertTrue(profileDecision.shouldAllowOpen)
        XCTAssertFalse(profileDecision.isUploadCandidate)
        XCTAssertTrue(otherAppDecision.shouldAllowOpen)
        XCTAssertFalse(otherAppDecision.isUploadCandidate)
    }

    func testWebUploadAuditModeRecordsWithoutBlocking() {
        let policy = VeloxPolicy(
            policyVersion: 11,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            webUploadControl: WebUploadControlConfig(mode: .auditOnly)
        )
        let engine = PolicyEngine(policy: policy)
        let safari = ProcessContext(
            pid: 404, parentPid: 1, uid: 501,
            signingId: "com.apple.Safari", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/System/Applications/Safari.app/Contents/MacOS/Safari"
        )

        let decision = engine.evaluateWebUploadOpen(
            process: safari,
            filePath: "/Users/alice/Desktop/demo.pdf",
            requestedFlags: UInt32(FREAD),
            isRegularFile: true
        )

        XCTAssertTrue(decision.shouldAllowOpen)
        XCTAssertTrue(decision.isUploadCandidate)
        XCTAssertEqual(decision.decisionString, "would-block")
    }

    func testWebUploadEnforcementDoesNotBlockAppOrExtensionBundlesInUserDirs() {
        let policy = VeloxPolicy(
            policyVersion: 12,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            webUploadControl: WebUploadControlConfig(mode: .enforce)
        )
        let engine = PolicyEngine(policy: policy)
        let safari = ProcessContext(
            pid: 406, parentPid: 1, uid: 501,
            signingId: "com.apple.Safari", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/System/Applications/Safari.app/Contents/MacOS/Safari"
        )

        // Safari inspecting an appex bundle inside ~/Downloads
        let appexDecision = engine.evaluateWebUploadOpen(
            process: safari,
            filePath: "/Users/alice/Downloads/DevProject/App.app/Contents/PlugIns/Extension.appex/Contents/MacOS/Extension",
            requestedFlags: UInt32(FREAD),
            isRegularFile: true
        )
        // Safari reading .DS_Store
        let dsStoreDecision = engine.evaluateWebUploadOpen(
            process: safari,
            filePath: "/Users/alice/Downloads/.DS_Store",
            requestedFlags: UInt32(FREAD),
            isRegularFile: true
        )

        XCTAssertTrue(appexDecision.shouldAllowOpen, "Appex components must be allowed to open")
        XCTAssertFalse(appexDecision.isUploadCandidate, "Appex components must never be treated as upload candidates")
        XCTAssertTrue(dsStoreDecision.shouldAllowOpen, ".DS_Store must be allowed to open")
        XCTAssertFalse(dsStoreDecision.isUploadCandidate, ".DS_Store must not be treated as upload candidate")
    }

    func testWebUploadEnforcementBlocksReadWithCloexecFlag() {
        let policy = VeloxPolicy(
            policyVersion: 13,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            webUploadControl: WebUploadControlConfig(mode: .enforce)
        )
        let engine = PolicyEngine(policy: policy)
        let webContent = ProcessContext(
            pid: 407, parentPid: 1, uid: 501,
            signingId: "com.apple.WebKit.WebContent", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.WebContent.xpc/Contents/MacOS/com.apple.WebKit.WebContent"
        )

        // 16777217 = FREAD (1) | O_CLOEXEC (0x01000000)
        let decision = engine.evaluateWebUploadOpen(
            process: webContent,
            filePath: "/Users/alice/Desktop/confidential.docx",
            requestedFlags: 16_777_217,
            isRegularFile: true
        )

        XCTAssertFalse(decision.shouldAllowOpen, "Read with O_CLOEXEC must be blocked in enforce mode")
        XCTAssertTrue(decision.isUploadCandidate)
        XCTAssertEqual(decision.decisionString, "blocked")
    }

    func testClipboardEvaluationBlocksProtectedFiles() {
        let policy = VeloxPolicy(
            policyVersion: 14,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            webUploadControl: WebUploadControlConfig(mode: .enforce)
        )
        let engine = PolicyEngine(policy: policy)

        let files = [
            "/Users/alice/Desktop/secret.pdf",
            "/Users/alice/Documents/financials.xlsx",
            "/tmp/scratch.txt"
        ]

        let decision = engine.evaluateClipboardContent(filePaths: files)
        XCTAssertTrue(decision.shouldBlock)
        XCTAssertEqual(decision.decisionString, "blocked")
        XCTAssertEqual(decision.blockedPaths.count, 2)
        XCTAssertTrue(decision.blockedPaths.contains("/Users/alice/Desktop/secret.pdf"))
        XCTAssertTrue(decision.blockedPaths.contains("/Users/alice/Documents/financials.xlsx"))
        XCTAssertEqual(decision.matchingRuleId, "clipboard-file-transfer")
    }

    func testClipboardEvaluationAuditOnly() {
        let policy = VeloxPolicy(
            policyVersion: 15,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            webUploadControl: WebUploadControlConfig(mode: .auditOnly)
        )
        let engine = PolicyEngine(policy: policy)

        let decision = engine.evaluateClipboardContent(filePaths: ["/Users/alice/Downloads/export.csv"])
        XCTAssertFalse(decision.shouldBlock, "Audit-only must not block clipboard")
        XCTAssertEqual(decision.decisionString, "would-block")
        XCTAssertEqual(decision.blockedPaths.count, 1)
    }

    func testClipboardEvaluationAllowsUnprotectedFiles() {
        let policy = VeloxPolicy(
            policyVersion: 16,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            webUploadControl: WebUploadControlConfig(mode: .enforce)
        )
        let engine = PolicyEngine(policy: policy)

        let decision = engine.evaluateClipboardContent(filePaths: ["/tmp/test.txt", "/Applications/Calculator.app"])
        XCTAssertFalse(decision.shouldBlock)
        XCTAssertEqual(decision.decisionString, "allowed")
        XCTAssertTrue(decision.blockedPaths.isEmpty)
    }

    func testClipboardEvaluationDisabledMode() {
        let policy = VeloxPolicy(
            policyVersion: 17,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            webUploadControl: WebUploadControlConfig(mode: .disabled)
        )
        let engine = PolicyEngine(policy: policy)

        let decision = engine.evaluateClipboardContent(filePaths: ["/Users/alice/Desktop/secret.pdf"])
        XCTAssertFalse(decision.shouldBlock)
        XCTAssertEqual(decision.decisionString, "allowed")
    }

    func testUSBMountEnforcementBlocksExternalDrive() {
        let policy = VeloxPolicy(
            policyVersion: 18,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            webUploadControl: WebUploadControlConfig(mode: .enforce),
            usbStorageControl: USBStorageControlConfig(mode: .enforce, blockExternalStorage: true)
        )
        let engine = PolicyEngine(policy: policy)
        let diskarbitrationd = ProcessContext(
            pid: 100, parentPid: 1, uid: 0,
            signingId: "com.apple.diskarbitrationd", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/usr/libexec/diskarbitrationd"
        )

        let decision = engine.evaluateMount(
            process: diskarbitrationd,
            mountFrom: "/dev/disk3s1",
            mountPoint: "/Volumes/USB_FLASH",
            fsType: "exfat",
            disposition: ES_MOUNT_DISPOSITION_EXTERNAL
        )

        XCTAssertFalse(decision.shouldAllowMount, "External USB mount must be blocked in enforce mode")
        XCTAssertTrue(decision.isUSBMountCandidate)
        XCTAssertEqual(decision.decisionString, "blocked")
        XCTAssertEqual(decision.dispositionString, "external")
        XCTAssertEqual(decision.matchingRuleId, "usb-storage-block-external")
    }

    func testUSBMountInternalDriveAlwaysAllowed() {
        let policy = VeloxPolicy(
            policyVersion: 19,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            webUploadControl: WebUploadControlConfig(mode: .enforce),
            usbStorageControl: USBStorageControlConfig(mode: .enforce, blockExternalStorage: true)
        )
        let engine = PolicyEngine(policy: policy)
        let kernel = ProcessContext(
            pid: 1, parentPid: 0, uid: 0,
            signingId: "com.apple.kernel", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/System/Library/Kernels/kernel"
        )

        let decision = engine.evaluateMount(
            process: kernel,
            mountFrom: "/dev/disk1s1",
            mountPoint: "/",
            fsType: "apfs",
            disposition: ES_MOUNT_DISPOSITION_INTERNAL
        )

        XCTAssertTrue(decision.shouldAllowMount, "Internal storage mount must NEVER be blocked")
        XCTAssertFalse(decision.isUSBMountCandidate)
        XCTAssertEqual(decision.decisionString, "allowed")
        XCTAssertEqual(decision.dispositionString, "internal")
    }

    func testUSBMountAuditOnlyMode() {
        let policy = VeloxPolicy(
            policyVersion: 20,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            webUploadControl: WebUploadControlConfig(mode: .enforce),
            usbStorageControl: USBStorageControlConfig(mode: .auditOnly, blockExternalStorage: true)
        )
        let engine = PolicyEngine(policy: policy)
        let diskarbitrationd = ProcessContext(
            pid: 100, parentPid: 1, uid: 0,
            signingId: "com.apple.diskarbitrationd", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/usr/libexec/diskarbitrationd"
        )

        let decision = engine.evaluateMount(
            process: diskarbitrationd,
            mountFrom: "/dev/disk4s1",
            mountPoint: "/Volumes/SANDISK",
            fsType: "msdos",
            disposition: ES_MOUNT_DISPOSITION_EXTERNAL
        )

        XCTAssertTrue(decision.shouldAllowMount, "Audit-only mode must allow mount")
        XCTAssertTrue(decision.isUSBMountCandidate)
        XCTAssertEqual(decision.decisionString, "would-block")
        XCTAssertEqual(decision.dispositionString, "external")
    }

    func testUSBMountDisabledMode() {
        let policy = VeloxPolicy(
            policyVersion: 21,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            webUploadControl: WebUploadControlConfig(mode: .enforce),
            usbStorageControl: USBStorageControlConfig(mode: .disabled, blockExternalStorage: true)
        )
        let engine = PolicyEngine(policy: policy)
        let diskarbitrationd = ProcessContext(
            pid: 100, parentPid: 1, uid: 0,
            signingId: "com.apple.diskarbitrationd", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/usr/libexec/diskarbitrationd"
        )

        let decision = engine.evaluateMount(
            process: diskarbitrationd,
            mountFrom: "/dev/disk4s1",
            mountPoint: "/Volumes/SANDISK",
            fsType: "msdos",
            disposition: ES_MOUNT_DISPOSITION_EXTERNAL
        )

        XCTAssertTrue(decision.shouldAllowMount)
        XCTAssertEqual(decision.decisionString, "allowed")
    }

    func testUSBPolicyStrictDecodingAndValidation() throws {
        let json = """
        {
            "policyVersion": 22,
            "applicationControl": {
                "mode": "enforce",
                "blockedApplications": [],
                "allowedApplications": []
            },
            "webUploadControl": {
                "mode": "enforce",
                "protectedDirectoryNames": ["Desktop", "Documents"]
            },
            "usbStorageControl": {
                "mode": "enforce",
                "blockExternalStorage": true
            }
        }
        """
        let data = json.data(using: .utf8)!
        let policy = try VeloxPolicy.decodeStrict(from: data)
        XCTAssertEqual(policy.policyVersion, 22)
        XCTAssertEqual(policy.usbStorageControl.mode, .enforce)
        XCTAssertTrue(policy.usbStorageControl.blockExternalStorage)
    }

    func testNearbyTransferBlocksProtectedFileReadBySharingd() {
        let policy = VeloxPolicy(
            policyVersion: 30,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            nearbyTransferControl: NearbyTransferControlConfig(mode: .enforce)
        )
        let engine = PolicyEngine(policy: policy)
        let sharingd = ProcessContext(
            pid: 500, parentPid: 1, uid: 501,
            signingId: "com.apple.sharingd", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/usr/libexec/sharingd"
        )

        let decision = engine.evaluateNearbyTransferOpen(
            process: sharingd,
            filePath: "/Users/alice/Documents/confidential.pdf",
            requestedFlags: UInt32(FREAD),
            isRegularFile: true
        )

        XCTAssertFalse(decision.shouldAllowOpen)
        XCTAssertTrue(decision.isTransferCandidate)
        XCTAssertEqual(decision.decisionString, "blocked")
        XCTAssertEqual(decision.matchingRuleId, "nearby-airdrop-file-read")
        XCTAssertEqual(decision.channel, "apple-sharing")
    }

    func testNearbyTransferBlocksProtectedFileReadByBluetoothFileExchange() {
        let policy = VeloxPolicy(
            policyVersion: 31,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            nearbyTransferControl: NearbyTransferControlConfig(mode: .enforce)
        )
        let engine = PolicyEngine(policy: policy)
        let bluetoothFileExchange = ProcessContext(
            pid: 501, parentPid: 1, uid: 501,
            signingId: "com.apple.BluetoothFileExchange", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/System/Applications/Utilities/Bluetooth File Exchange.app/Contents/MacOS/Bluetooth File Exchange"
        )

        let decision = engine.evaluateNearbyTransferOpen(
            process: bluetoothFileExchange,
            filePath: "/Users/alice/Desktop/roadmap.xlsx",
            requestedFlags: UInt32(FREAD),
            isRegularFile: true
        )

        XCTAssertFalse(decision.shouldAllowOpen)
        XCTAssertTrue(decision.isTransferCandidate)
        XCTAssertEqual(decision.decisionString, "blocked")
        XCTAssertEqual(decision.matchingRuleId, "nearby-bluetooth-file-read")
        XCTAssertEqual(decision.channel, "bluetooth")
    }

    func testNearbyTransferAllowsIncomingWriteAccess() {
        let policy = VeloxPolicy(
            policyVersion: 32,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            nearbyTransferControl: NearbyTransferControlConfig(mode: .enforce)
        )
        let engine = PolicyEngine(policy: policy)
        let obexAgent = ProcessContext(
            pid: 502, parentPid: 1, uid: 501,
            signingId: "com.apple.OBEXAgent", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/System/Library/CoreServices/OBEXAgent.app/Contents/MacOS/OBEXAgent"
        )

        let decision = engine.evaluateNearbyTransferOpen(
            process: obexAgent,
            filePath: "/Users/alice/Downloads/incoming.pdf",
            requestedFlags: UInt32(FWRITE),
            isRegularFile: true
        )

        XCTAssertTrue(decision.shouldAllowOpen)
        XCTAssertFalse(decision.isTransferCandidate)
        XCTAssertEqual(decision.decisionString, "allowed")
    }

    func testNearbyTransferDoesNotBlockOrdinaryApplicationRead() {
        let policy = VeloxPolicy(
            policyVersion: 33,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            nearbyTransferControl: NearbyTransferControlConfig(mode: .enforce)
        )
        let engine = PolicyEngine(policy: policy)
        let preview = ProcessContext(
            pid: 503, parentPid: 1, uid: 501,
            signingId: "com.apple.Preview", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/System/Applications/Preview.app/Contents/MacOS/Preview"
        )

        let decision = engine.evaluateNearbyTransferOpen(
            process: preview,
            filePath: "/Users/alice/Documents/confidential.pdf",
            requestedFlags: UInt32(FREAD),
            isRegularFile: true
        )

        XCTAssertTrue(decision.shouldAllowOpen)
        XCTAssertFalse(decision.isTransferCandidate)
        XCTAssertNil(decision.channel)
    }

    func testNearbyTransferAuditOnlyRecordsWithoutBlocking() {
        let policy = VeloxPolicy(
            policyVersion: 34,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            nearbyTransferControl: NearbyTransferControlConfig(mode: .auditOnly)
        )
        let engine = PolicyEngine(policy: policy)
        let airDrop = ProcessContext(
            pid: 504, parentPid: 1, uid: 501,
            signingId: "com.apple.finder.Open-AirDrop", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/System/Library/CoreServices/Finder.app/Contents/Applications/AirDrop.app/Contents/MacOS/AirDrop"
        )

        let decision = engine.evaluateNearbyTransferOpen(
            process: airDrop,
            filePath: "/Users/alice/Pictures/diagram.png",
            requestedFlags: UInt32(FREAD),
            isRegularFile: true
        )

        XCTAssertTrue(decision.shouldAllowOpen)
        XCTAssertTrue(decision.isTransferCandidate)
        XCTAssertEqual(decision.decisionString, "would-block")
        XCTAssertEqual(decision.channel, "airdrop")
    }

    func testNearbyTransferDisabledModeAllowsRead() {
        let policy = VeloxPolicy(
            policyVersion: 35,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            nearbyTransferControl: NearbyTransferControlConfig(mode: .disabled)
        )
        let engine = PolicyEngine(policy: policy)
        let sharingd = ProcessContext(
            pid: 505, parentPid: 1, uid: 501,
            signingId: "com.apple.sharingd", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/usr/libexec/sharingd"
        )

        let decision = engine.evaluateNearbyTransferOpen(
            process: sharingd,
            filePath: "/Users/alice/Documents/confidential.pdf",
            requestedFlags: UInt32(FREAD),
            isRegularFile: true
        )

        XCTAssertTrue(decision.shouldAllowOpen)
        XCTAssertFalse(decision.isTransferCandidate)
        XCTAssertEqual(decision.decisionString, "allowed")
    }

    func testNearbyTransferHonorsPerChannelSwitch() {
        let policy = VeloxPolicy(
            policyVersion: 36,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            nearbyTransferControl: NearbyTransferControlConfig(
                mode: .enforce,
                blockAirDrop: false,
                blockBluetoothFileTransfer: true
            )
        )
        let engine = PolicyEngine(policy: policy)
        let sharingd = ProcessContext(
            pid: 506, parentPid: 1, uid: 501,
            signingId: "com.apple.sharingd", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/usr/libexec/sharingd"
        )

        let decision = engine.evaluateNearbyTransferOpen(
            process: sharingd,
            filePath: "/Users/alice/Documents/confidential.pdf",
            requestedFlags: UInt32(FREAD),
            isRegularFile: true
        )

        XCTAssertTrue(decision.shouldAllowOpen)
        XCTAssertFalse(decision.isTransferCandidate)
        XCTAssertEqual(decision.channel, "apple-sharing")
    }

    func testNearbyTransferPolicyStrictDecodingAndUnknownPropertyRejection() throws {
        let json = """
        {
            "policyVersion": 37,
            "applicationControl": {
                "mode": "enforce",
                "blockedApplications": [],
                "allowedApplications": []
            },
            "nearbyTransferControl": {
                "mode": "audit-only",
                "blockAirDrop": true,
                "blockBluetoothFileTransfer": false,
                "protectedDirectoryNames": ["Desktop", "Documents"]
            }
        }
        """
        let policy = try VeloxPolicy.decodeStrict(from: Data(json.utf8))
        XCTAssertEqual(policy.nearbyTransferControl.mode, .auditOnly)
        XCTAssertTrue(policy.nearbyTransferControl.blockAirDrop)
        XCTAssertFalse(policy.nearbyTransferControl.blockBluetoothFileTransfer)
        XCTAssertEqual(policy.nearbyTransferControl.protectedDirectoryNames, ["Desktop", "Documents"])

        let invalidJSON = json.replacingOccurrences(
            of: "\"protectedDirectoryNames\": [\"Desktop\", \"Documents\"]",
            with: "\"protectedDirectoryNames\": [\"Desktop\"], \"unexpected\": true"
        )
        XCTAssertThrowsError(try VeloxPolicy.decodeStrict(from: Data(invalidJSON.utf8)))
    }

    func testClipboardBlockAllClearsEverySource() {
        let policy = VeloxPolicy(
            policyVersion: 40,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            clipboardControl: ClipboardControlConfig(mode: .blockAll)
        )
        let engine = PolicyEngine(policy: policy)
        let notes = ProcessContext(
            pid: 700, parentPid: 1, uid: 501,
            signingId: "com.apple.Notes", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/System/Applications/Notes.app/Contents/MacOS/Notes"
        )

        let decision = engine.evaluateClipboardCopy(source: notes)

        XCTAssertTrue(decision.shouldClearPasteboard)
        XCTAssertEqual(decision.decisionString, "blocked")
        XCTAssertEqual(decision.matchingRuleId, "clipboard-block-all")
        XCTAssertEqual(decision.policyVersion, 40)
    }

    func testClipboardSelectedApplicationsMatchesSignedSourceOnly() {
        let rule = ApplicationRule(
            ruleId: "clipboard-block-notes",
            signingId: "com.apple.Notes"
        )
        let policy = VeloxPolicy(
            policyVersion: 41,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            clipboardControl: ClipboardControlConfig(
                mode: .blockSelectedApplications,
                blockedApplications: [rule]
            )
        )
        let engine = PolicyEngine(policy: policy)
        let notes = ProcessContext(
            pid: 701, parentPid: 1, uid: 501,
            signingId: "com.apple.Notes", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/System/Applications/Notes.app/Contents/MacOS/Notes"
        )
        let textEdit = ProcessContext(
            pid: 702, parentPid: 1, uid: 501,
            signingId: "com.apple.TextEdit", teamId: nil,
            isPlatformBinary: true, cdhash: nil,
            executablePath: "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit"
        )

        let blocked = engine.evaluateClipboardCopy(source: notes)
        let allowed = engine.evaluateClipboardCopy(source: textEdit)

        XCTAssertTrue(blocked.shouldClearPasteboard)
        XCTAssertEqual(blocked.matchingRuleId, "clipboard-block-notes")
        XCTAssertFalse(allowed.shouldClearPasteboard)
        XCTAssertEqual(allowed.decisionString, "allowed")
    }

    func testClipboardDisabledAllowsCopy() {
        let policy = VeloxPolicy(
            policyVersion: 42,
            applicationControl: ApplicationControlConfig(mode: .enforce),
            clipboardControl: ClipboardControlConfig(mode: .disabled)
        )
        let engine = PolicyEngine(policy: policy)
        let source = ProcessContext(
            pid: 703, parentPid: 1, uid: 501,
            signingId: "com.example.app", teamId: "EXAMPLETEAM",
            isPlatformBinary: false, cdhash: nil,
            executablePath: "/Applications/Example.app/Contents/MacOS/Example"
        )

        XCTAssertFalse(engine.evaluateClipboardCopy(source: source).shouldClearPasteboard)
    }

    func testClipboardPolicyStrictDecodingAndUnknownPropertyRejection() throws {
        let json = """
        {
            "policyVersion": 43,
            "applicationControl": { "mode": "enforce" },
            "clipboardControl": {
                "mode": "block-selected-apps",
                "blockedApplications": [
                    { "ruleId": "clipboard-notes", "signingId": "com.apple.Notes" }
                ]
            }
        }
        """
        let policy = try VeloxPolicy.decodeStrict(from: Data(json.utf8))
        XCTAssertEqual(policy.clipboardControl.mode, .blockSelectedApplications)
        XCTAssertEqual(policy.clipboardControl.blockedApplications.count, 1)

        let invalidJSON = json.replacingOccurrences(
            of: "\"blockedApplications\": [",
            with: "\"unexpected\": true, \"blockedApplications\": ["
        )
        XCTAssertThrowsError(try VeloxPolicy.decodeStrict(from: Data(invalidJSON.utf8)))
    }
}
