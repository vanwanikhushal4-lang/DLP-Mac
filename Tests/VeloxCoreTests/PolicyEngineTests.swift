import XCTest
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
}
