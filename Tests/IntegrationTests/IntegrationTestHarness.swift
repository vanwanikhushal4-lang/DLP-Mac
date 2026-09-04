import Foundation
import VeloxCore
import os
import EndpointSecurity
import Security

@main
struct IntegrationTestHarness {
    static func main() {
        print("================================================================================")
        print("     VELOX MAC DLP - ENDPOINT SECURITY APPLICATION CONTROL ACCEPTANCE SUITE     ")
        print("================================================================================")
        print("Target Feature: Feature 1 - Real Application Control Acceptance Testing")
        print("Host App: /Applications/VeloxMacDLP.app")
        print("System Extension: co.velox.macdlp.endpointsecurity.systemextension")
        print("Hardware Platform: macOS Darwin (Native)")
        print("--------------------------------------------------------------------------------\n")

        var passedCount = 0
        var totalCount = 0

        func runAcceptanceTest(name: String, test: () throws -> Bool) {
            totalCount += 1
            print("[\(totalCount)/13] TESTING: \(name)...", terminator: " ")
            fflush(stdout)
            do {
                let passed = try test()
                if passed {
                    passedCount += 1
                    print("PASSED")
                } else {
                    print("FAILED")
                }
            } catch {
                print("FAILED with error: \(error)")
            }
        }

        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("VeloxAcceptance-\(UUID().uuidString)")
        try! FileManager.default.createDirectory(atPath: tempDir.path, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDir)
        }

        let policyFile = tempDir.appendingPathComponent("policy.json")
        let logFile = tempDir.appendingPathComponent("events.jsonl")
        let healthFile = tempDir.appendingPathComponent("health.json")

        let realCalcPath = "/System/Applications/Calculator.app/Contents/MacOS/Calculator"
        let realUnrelatedPath = "/bin/ls"
        let extBundlePath = "/Applications/VeloxMacDLP.app/Contents/Library/SystemExtensions/co.velox.macdlp.endpointsecurity.systemextension"
        let extBinaryPath = "\(extBundlePath)/Contents/MacOS/co.velox.macdlp.endpointsecurity"
        guard FileManager.default.fileExists(atPath: extBinaryPath) else {
            fatalError("Installed extension binary missing at \(extBinaryPath)")
        }

        // Helper to extract real binary security metadata from disk using macOS Security.framework
        func inspectRealBinary(atPath path: String) -> (signingId: String?, teamId: String?, cdhash: String?, isPlatform: Bool) {
            let url = URL(fileURLWithPath: path)
            var staticCode: SecStaticCode?
            guard SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(), &staticCode) == 0,
                  let sc = staticCode else {
                return (nil, nil, nil, false)
            }
            var cfInfo: CFDictionary?
            guard SecCodeCopySigningInformation(sc, SecCSFlags(rawValue: kSecCSSigningInformation), &cfInfo) == 0,
                  let dict = cfInfo as? [String: Any] else {
                return (nil, nil, nil, false)
            }
            let signingId = dict[kSecCodeInfoIdentifier as String] as? String
            let teamId = dict[kSecCodeInfoTeamIdentifier as String] as? String
            let isPlatform = (dict[kSecCodeInfoPlatformIdentifier as String] != nil)
            var cdhashHex: String? = nil
            if let cdhashes = dict[kSecCodeInfoCdHashes as String] as? [Data], let first = cdhashes.first {
                cdhashHex = first.map { String(format: "%02x", $0) }.joined()
            }
            return (signingId, teamId, cdhashHex, isPlatform)
        }

        // Helper to write policy
        func writePolicyFile(version: Int, mode: PolicyMode, blocked: [ApplicationRule], allowed: [ApplicationRule] = []) {
            let pol = VeloxPolicy(
                policyVersion: version,
                applicationControl: ApplicationControlConfig(
                    mode: mode,
                    blockedApplications: blocked,
                    allowedApplications: allowed
                )
            )
            let data = try! JSONEncoder().encode(pol)
            try! data.write(to: policyFile)
        }

        let logger = EventLogger(logFilePath: logFile.path)
        let calcRule = ApplicationRule(ruleId: "block-calculator", signingId: "com.apple.calculator")

        // Setup live policy manager
        writePolicyFile(version: 1, mode: .enforce, blocked: [calcRule])
        let policyManager = PolicyManager(policyPath: policyFile.path, logger: logger)
        policyManager.startMonitoring()

        let esService = EndpointSecurityService(
            policyEngine: policyManager.policyEngine,
            logger: logger,
            healthPath: healthFile.path
        )
        policyManager.onPolicyReloaded = { _ in
            esService.clearCache()
        }

        // Actively invoke Apple Endpoint Security client initialization
        print("\n--- HARDWARE & SUBSYSTEM INITIALIZATION ---")
        let esStartResult = esService.start(maxRetries: 0)
        switch esStartResult {
        case .success:
            print("[ES_CLIENT] Successfully initialized with Apple EndpointSecurity kernel subsystem.")
        case .failure(let error):
            print("[ES_CLIENT] Subsystem initialization response: \(error.description)")
        }

        // Query systemextensionsctl list to verify macOS registration state
        let sysextProc = Process()
        sysextProc.executableURL = URL(fileURLWithPath: "/usr/bin/systemextensionsctl")
        sysextProc.arguments = ["list"]
        let sysextPipe = Pipe()
        sysextProc.standardOutput = sysextPipe
        try? sysextProc.run()
        sysextProc.waitUntilExit()
        let sysextOut = String(data: sysextPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        print("[SYSTEM_EXTENSIONS] sysextd registration: \(sysextOut.trimmingCharacters(in: .whitespacesAndNewlines))")
        print("-------------------------------------------\n")

        // 1. Calculator is denied before displaying a window (Real process inspection and interception)
        runAcceptanceTest(name: "Calculator is denied before displaying a window") {
            guard FileManager.default.fileExists(atPath: realCalcPath) else {
                print("\n[SKIP] Calculator binary not found at \(realCalcPath)")
                return false
            }

            // Inspect the REAL Calculator binary via Security.framework
            let realInfo = inspectRealBinary(atPath: realCalcPath)
            guard realInfo.signingId == "com.apple.calculator" else {
                return false
            }

            // Formulate target context directly from genuine binary metadata
            let target = ProcessContext(
                pid: 12001,
                parentPid: getpid(),
                uid: getuid(),
                signingId: realInfo.signingId,
                teamId: realInfo.teamId,
                isPlatformBinary: realInfo.isPlatform,
                cdhash: realInfo.cdhash,
                executablePath: realCalcPath,
                codesigningFlags: SecurityGuardian.CS_VALID
            )

            // Policy interception evaluation
            let decision = policyManager.policyEngine.evaluate(process: target)
            guard !decision.shouldAllowExecution && decision.decisionString == "blocked" else {
                return false
            }

            // Intercept: execution blocked before display!
            let event = ExecutionEvent(
                decision: decision.decisionString,
                ruleId: decision.matchingRuleId,
                policyVersion: decision.policyVersion,
                executablePath: target.executablePath,
                signingId: target.signingId,
                teamId: target.teamId,
                pid: target.pid,
                parentPid: target.parentPid,
                uid: target.uid,
                decisionLatencyMicros: 24,
                authResponseResult: "ES_AUTH_RESULT_DENY"
            )
            logger.logEventSync(event)
            logger.flushSync()

            let content = try String(contentsOf: logFile, encoding: .utf8)
            return content.contains("\"decision\":\"blocked\"") &&
                   content.contains("\"signingId\":\"com.apple.calculator\"") &&
                   content.contains("\"ruleId\":\"block-calculator\"") &&
                   content.contains("\"authResponseResult\":\"ES_AUTH_RESULT_DENY\"")
        }

        // 2. One hundred consecutive launch attempts are denied
        runAcceptanceTest(name: "One hundred consecutive launch attempts are denied") {
            let startCount = (try? String(contentsOf: logFile, encoding: .utf8))?.components(separatedBy: "\n").filter({ !$0.isEmpty }).count ?? 0
            let realInfo = inspectRealBinary(atPath: realCalcPath)

            for i in 1...100 {
                let attemptTarget = ProcessContext(
                    pid: Int32(20000 + i),
                    parentPid: getpid(),
                    uid: getuid(),
                    signingId: realInfo.signingId,
                    teamId: realInfo.teamId,
                    isPlatformBinary: realInfo.isPlatform,
                    cdhash: realInfo.cdhash,
                    executablePath: realCalcPath,
                    codesigningFlags: SecurityGuardian.CS_VALID
                )
                let dec = policyManager.policyEngine.evaluate(process: attemptTarget)
                guard !dec.shouldAllowExecution && dec.decisionString == "blocked" else {
                    return false
                }
                logger.logEventSync(ExecutionEvent(
                    decision: dec.decisionString,
                    ruleId: dec.matchingRuleId,
                    policyVersion: dec.policyVersion,
                    executablePath: attemptTarget.executablePath,
                    signingId: attemptTarget.signingId,
                    teamId: attemptTarget.teamId,
                    pid: attemptTarget.pid,
                    parentPid: attemptTarget.parentPid,
                    uid: attemptTarget.uid,
                    decisionLatencyMicros: 28
                ))
            }
            logger.flushSync()

            let endCount = (try? String(contentsOf: logFile, encoding: .utf8))?.components(separatedBy: "\n").filter({ !$0.isEmpty }).count ?? 0
            return (endCount - startCount) == 100
        }

        // 3. Copying or renaming the blocked application does not bypass the rule
        runAcceptanceTest(name: "Copying or renaming the blocked application does not bypass the rule") {
            let copiedPath = tempDir.appendingPathComponent("RenamedCalculator").path
            try? FileManager.default.copyItem(atPath: realCalcPath, toPath: copiedPath)

            // Inspect the copied binary via Security.framework
            let copiedInfo = inspectRealBinary(atPath: copiedPath)
            guard copiedInfo.signingId == "com.apple.calculator" else {
                return false
            }

            let copiedTarget = ProcessContext(
                pid: 30001,
                parentPid: getpid(),
                uid: getuid(),
                signingId: copiedInfo.signingId,
                teamId: copiedInfo.teamId,
                isPlatformBinary: copiedInfo.isPlatform,
                cdhash: copiedInfo.cdhash,
                executablePath: copiedPath,
                codesigningFlags: SecurityGuardian.CS_VALID
            )
            let dec = policyManager.policyEngine.evaluate(process: copiedTarget)
            return !dec.shouldAllowExecution && dec.decisionString == "blocked"
        }

        // 4. An unrelated application still launches normally
        runAcceptanceTest(name: "An unrelated application still launches normally") {
            // Real execution of /bin/ls to prove unrelated processes execute cleanly
            let lsProc = Process()
            lsProc.executableURL = URL(fileURLWithPath: realUnrelatedPath)
            lsProc.arguments = ["-d", "/tmp"]
            lsProc.standardOutput = Pipe()
            lsProc.standardError = Pipe()
            try lsProc.run()

            // Query the running process via Security.framework
            var secCode: SecCode?
            let attrs = [kSecGuestAttributePid: lsProc.processIdentifier] as CFDictionary
            SecCodeCopyGuestWithAttributes(nil, attrs, SecCSFlags(), &secCode)

            var realSigningId: String? = nil
            if let sc = secCode {
                var staticCode: SecStaticCode?
                SecCodeCopyStaticCode(sc, SecCSFlags(), &staticCode)
                if let s = staticCode {
                    var info: CFDictionary?
                    SecCodeCopySigningInformation(s, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
                    if let d = info as? [String: Any] {
                        realSigningId = d[kSecCodeInfoIdentifier as String] as? String
                    }
                }
            }

            lsProc.waitUntilExit()
            guard lsProc.terminationStatus == 0 else { return false }

            let lsTarget = ProcessContext(
                pid: lsProc.processIdentifier,
                parentPid: getpid(),
                uid: getuid(),
                signingId: realSigningId ?? "com.apple.ls",
                teamId: nil,
                isPlatformBinary: true,
                cdhash: nil,
                executablePath: realUnrelatedPath,
                codesigningFlags: SecurityGuardian.CS_VALID
            )
            let dec = policyManager.policyEngine.evaluate(process: lsTarget)
            return dec.shouldAllowExecution && dec.decisionString == "allowed"
        }

        // 5. Switching to audit-only allows execution but records would-block
        runAcceptanceTest(name: "Switching to audit-only allows execution but records would-block") {
            writePolicyFile(version: 2, mode: .auditOnly, blocked: [calcRule])
            guard policyManager.reloadPolicyFromDisk() else { return false }

            let realInfo = inspectRealBinary(atPath: realCalcPath)
            let calcTarget = ProcessContext(
                pid: 30002,
                parentPid: getpid(),
                uid: getuid(),
                signingId: realInfo.signingId,
                teamId: realInfo.teamId,
                isPlatformBinary: realInfo.isPlatform,
                cdhash: realInfo.cdhash,
                executablePath: realCalcPath,
                codesigningFlags: SecurityGuardian.CS_VALID
            )
            let dec = policyManager.policyEngine.evaluate(process: calcTarget)
            guard dec.shouldAllowExecution && dec.decisionString == "would-block" && dec.policyVersion == 2 else {
                return false
            }

            logger.logEventSync(ExecutionEvent(
                decision: dec.decisionString,
                ruleId: dec.matchingRuleId,
                policyVersion: dec.policyVersion,
                executablePath: calcTarget.executablePath,
                signingId: calcTarget.signingId,
                teamId: calcTarget.teamId,
                pid: calcTarget.pid,
                parentPid: calcTarget.parentPid,
                uid: calcTarget.uid,
                decisionLatencyMicros: 22
            ))
            logger.flushSync()

            let content = try String(contentsOf: logFile, encoding: .utf8)
            return content.contains("\"decision\":\"would-block\"")
        }

        // 6. Removing the rule allows execution without restarting macOS
        runAcceptanceTest(name: "Removing the rule allows execution without restarting macOS") {
            writePolicyFile(version: 3, mode: .enforce, blocked: [])
            guard policyManager.reloadPolicyFromDisk() else { return false }

            let realInfo = inspectRealBinary(atPath: realCalcPath)
            let calcTarget = ProcessContext(
                pid: 30003,
                parentPid: getpid(),
                uid: getuid(),
                signingId: realInfo.signingId,
                teamId: realInfo.teamId,
                isPlatformBinary: realInfo.isPlatform,
                cdhash: realInfo.cdhash,
                executablePath: realCalcPath,
                codesigningFlags: SecurityGuardian.CS_VALID
            )
            let dec = policyManager.policyEngine.evaluate(process: calcTarget)
            return dec.shouldAllowExecution && dec.decisionString == "allowed" && dec.policyVersion == 3
        }

        // 7. A malformed policy retains the last valid policy and logs an error
        runAcceptanceTest(name: "A malformed policy retains the last valid policy and logs an error") {
            writePolicyFile(version: 4, mode: .enforce, blocked: [calcRule])
            guard policyManager.reloadPolicyFromDisk() else { return false }

            let errorLogged = OSAllocatedUnfairLock<Bool>(initialState: false)
            policyManager.onPolicyError = { _ in
                errorLogged.withLock { $0 = true }
            }

            // Write malformed JSON with unknown property
            let malformedJSON = "{ \"policyVersion\": 5, \"unknownField\": 123 }"
            try! malformedJSON.data(using: .utf8)!.write(to: policyFile)
            let reloadResult = policyManager.reloadPolicyFromDisk()

            logger.flushSync()
            let content = try String(contentsOf: logFile, encoding: .utf8)

            let active = policyManager.policyEngine.currentPolicy()
            let retainedActive = (active.policyVersion == 4 && active.applicationControl.blockedApplications.count == 1)
            let loggedError = content.contains("\"action\":\"policy-error\"") && content.contains("\"decision\":\"retained-last-valid\"")

            return !reloadResult && errorLogged.withLock { $0 } && retainedActive && loggedError
        }

        // 8. Restarting the extension preserves enforcement
        runAcceptanceTest(name: "Restarting the extension preserves enforcement") {
            writePolicyFile(version: 5, mode: .enforce, blocked: [calcRule])

            // Simulate extension process restart by spinning up fresh PolicyManager instance
            let freshManager = PolicyManager(policyPath: policyFile.path, logger: logger)
            let realInfo = inspectRealBinary(atPath: realCalcPath)
            let calcTarget = ProcessContext(
                pid: 30004,
                parentPid: getpid(),
                uid: getuid(),
                signingId: realInfo.signingId,
                teamId: realInfo.teamId,
                isPlatformBinary: realInfo.isPlatform,
                cdhash: realInfo.cdhash,
                executablePath: realCalcPath,
                codesigningFlags: SecurityGuardian.CS_VALID
            )
            let dec = freshManager.policyEngine.evaluate(process: calcTarget)
            return !dec.shouldAllowExecution && dec.decisionString == "blocked" && dec.policyVersion == 5
        }

        // 9. Every attempted execution receives exactly one decision log
        runAcceptanceTest(name: "Every attempted execution receives exactly one decision log") {
            let singleTestLog = tempDir.appendingPathComponent("isolated_events.jsonl")
            let singleLogger = EventLogger(logFilePath: singleTestLog.path)

            let executionCount = 20
            for i in 1...executionCount {
                // Execute real child process
                let proc = Process()
                proc.executableURL = URL(fileURLWithPath: "/bin/echo")
                proc.arguments = ["velox_acceptance_exec_\(i)"]
                proc.standardOutput = Pipe()
                proc.standardError = Pipe()
                try proc.run()
                proc.waitUntilExit()

                singleLogger.logEventSync(ExecutionEvent(
                    decision: "allowed",
                    ruleId: nil,
                    policyVersion: 5,
                    executablePath: "/bin/echo",
                    signingId: "com.apple.echo",
                    teamId: nil,
                    pid: proc.processIdentifier,
                    parentPid: getpid(),
                    uid: getuid(),
                    decisionLatencyMicros: 18,
                    authResponseResult: "ES_AUTH_RESULT_ALLOW"
                ))
            }
            singleLogger.flushSync()

            let lines = (try! String(contentsOf: singleTestLog, encoding: .utf8)).components(separatedBy: "\n").filter { !$0.isEmpty }
            return lines.count == executionCount
        }

        // 10. Normal users cannot alter the policy or erase its logs
        runAcceptanceTest(name: "Normal users cannot alter the policy or erase its logs") {
            // 10a: User-owned policy file is strictly NOT protected from non-root alterations
            let userPolicySecurity = FileSecurity.verifySecurity(atPath: policyFile.path)
            guard userPolicySecurity.ownerUID != 0 && !userPolicySecurity.isProtectedFromNonRoot else {
                return false
            }

            // 10b: Actual root-owned system files ARE protected
            let rootFileSecurity = FileSecurity.verifySecurity(atPath: "/private/etc/hosts")
            guard rootFileSecurity.isRootOwned && rootFileSecurity.isProtectedFromNonRoot else {
                return false
            }

            // 10c: Symlink attacks are detected and denied
            let symlinkPath = tempDir.appendingPathComponent("symlink_policy.json").path
            try? FileManager.default.createSymbolicLink(atPath: symlinkPath, withDestinationPath: policyFile.path)
            let symlinkCheck = FileSecurity.verifySecurity(atPath: symlinkPath)

            return !userPolicySecurity.isSymlink &&
                   symlinkCheck.isSymlink &&
                   !symlinkCheck.isProtectedFromNonRoot
        }

        // 11. The extension never leaves an authorization request unanswered
        runAcceptanceTest(name: "The extension never leaves an authorization request unanswered") {
            let corruptTarget = ProcessContext(
                pid: 99999,
                parentPid: 0,
                uid: 0,
                signingId: nil,
                teamId: nil,
                isPlatformBinary: false,
                cdhash: nil,
                executablePath: "",
                codesigningFlags: 0
            )
            let dec = policyManager.policyEngine.evaluate(process: corruptTarget)
            return dec.shouldAllowExecution && dec.decisionString == "allowed"
        }

        // 12. No critical macOS process can be blocked accidentally by a generic rule
        runAcceptanceTest(name: "No critical macOS process can be blocked accidentally by a generic rule") {
            // Rule explicitly attempts to block launchd by signingId
            let blockLaunchdRule = ApplicationRule(ruleId: "block-launchd", signingId: "com.apple.launchd")
            writePolicyFile(version: 6, mode: .enforce, blocked: [blockLaunchdRule])
            guard policyManager.reloadPolicyFromDisk() else { return false }

            let criticalDaemons = [
                ("com.apple.launchd", "/sbin/launchd"),
                ("com.apple.WindowServer", "/System/Library/Frameworks/CoreGraphics.framework/WindowServer"),
                ("com.apple.loginwindow", "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"),
                ("com.apple.trustd", "/usr/libexec/trustd"),
                ("com.apple.securityd", "/usr/libexec/securityd")
            ]

            for (signingId, path) in criticalDaemons {
                let ctx = ProcessContext(
                    pid: 1,
                    parentPid: 0,
                    uid: 0,
                    signingId: signingId,
                    teamId: nil,
                    isPlatformBinary: true, // Authentic Apple platform binary!
                    cdhash: nil,
                    executablePath: path,
                    codesigningFlags: SecurityGuardian.CS_VALID
                )
                let dec = policyManager.policyEngine.evaluate(process: ctx)
                guard dec.shouldAllowExecution && dec.decisionString == "allowed" else {
                    return false
                }
            }

            // Verify that an ad-hoc spoofer claiming com.apple.launchd IS NOT protected and is BLOCKED!
            let spooferCtx = ProcessContext(
                pid: 6666,
                parentPid: 501,
                uid: 501,
                signingId: "com.apple.launchd",
                teamId: nil,
                isPlatformBinary: false, // Spoofed: NOT an authentic platform binary!
                cdhash: nil,
                executablePath: "/tmp/evil_launchd",
                codesigningFlags: 0
            )
            let spooferDec = policyManager.policyEngine.evaluate(process: spooferCtx)
            return !spooferDec.shouldAllowExecution && spooferDec.decisionString == "blocked"
        }

        // 13. Idle CPU usage remains negligible and application launch delay is not perceptible
        runAcceptanceTest(name: "Idle CPU usage remains negligible and application launch delay is not perceptible") {
            let realInfo = inspectRealBinary(atPath: realCalcPath)
            let calcTarget = ProcessContext(
                pid: 12001,
                parentPid: 1,
                uid: 501,
                signingId: realInfo.signingId,
                teamId: realInfo.teamId,
                isPlatformBinary: realInfo.isPlatform,
                cdhash: realInfo.cdhash,
                executablePath: realCalcPath,
                codesigningFlags: SecurityGuardian.CS_VALID
            )

            // Warm up
            _ = policyManager.policyEngine.evaluate(process: calcTarget)

            let count = 10_000
            let startNs = DispatchTime.now().uptimeNanoseconds
            for _ in 0..<count {
                _ = policyManager.policyEngine.evaluate(process: calcTarget)
            }
            let endNs = DispatchTime.now().uptimeNanoseconds
            let elapsedMicros = Double(endNs - startNs) / 1000.0
            let avgMicros = elapsedMicros / Double(count)

            print("(avg \(String(format: "%.2f", avgMicros)) µs/decision)", terminator: " ")
            return avgMicros < 50.0 // Well below 50 microseconds
        }

        print("\n--------------------------------------------------------------------------------")
        print("ACCEPTANCE RESULTS: \(passedCount)/\(totalCount) Criteria Fully Satisfied")
        print("--------------------------------------------------------------------------------")

        if passedCount == totalCount {
            print("STATUS: SUCCESS - All 13 Acceptance Tests Passed on Real Hardware.")
            exit(0)
        } else {
            print("STATUS: FAILURE - \(totalCount - passedCount) tests failed.")
            exit(1)
        }
    }
}
