import XCTest
@testable import VeloxCore

final class PrintToPDFControlTests: XCTestCase {
    private func engine(mode: PolicyMode, enabled: Bool = true) -> PolicyEngine {
        PolicyEngine(
            policy: VeloxPolicy(
                policyVersion: 42,
                applicationControl: ApplicationControlConfig(mode: .disabled),
                printToPDFControl: PrintToPDFControlConfig(
                    mode: mode,
                    blockSaveAsPDF: enabled
                )
            )
        )
    }

    private func process(
        signingId: String = "com.microsoft.Word",
        teamId: String? = "UBF8T346G9",
        isPlatformBinary: Bool = false,
        executablePath: String = "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word",
        codesigningFlags: UInt32 = 1
    ) -> ProcessContext {
        ProcessContext(
            pid: 1234,
            parentPid: 1,
            uid: 501,
            signingId: signingId,
            teamId: teamId,
            isPlatformBinary: isPlatformBinary,
            executablePath: executablePath,
            codesigningFlags: codesigningFlags
        )
    }

    func testEnforceBlocksNewPDFOutputInUserContentFolder() {
        let decision = engine(mode: .enforce).evaluatePrintToPDFCreate(
            process: process(),
            destinationPath: "/Users/alice/Documents/board-report.PDF"
        )

        XCTAssertEqual(decision.decisionString, "blocked")
        XCTAssertFalse(decision.shouldAllowCreate)
        XCTAssertTrue(decision.isPDFOutputCandidate)
        XCTAssertEqual(decision.matchingRuleId, "print-to-pdf-file-create")
        XCTAssertEqual(decision.policyVersion, 42)
    }

    func testAuditOnlyRecordsWithoutDenyingCreate() {
        let decision = engine(mode: .auditOnly).evaluatePrintToPDFCreate(
            process: process(),
            destinationPath: "/Users/alice/Desktop/report.pdf"
        )

        XCTAssertEqual(decision.decisionString, "would-block")
        XCTAssertTrue(decision.shouldAllowCreate)
        XCTAssertTrue(decision.isPDFOutputCandidate)
    }

    func testDisabledOrBooleanOffAllowsPDFOutput() {
        let disabled = engine(mode: .disabled).evaluatePrintToPDFCreate(
            process: process(),
            destinationPath: "/Users/alice/Downloads/report.pdf"
        )
        let switchOff = engine(mode: .enforce, enabled: false).evaluatePrintToPDFCreate(
            process: process(),
            destinationPath: "/Users/alice/Downloads/report.pdf"
        )

        XCTAssertTrue(disabled.shouldAllowCreate)
        XCTAssertFalse(disabled.isPDFOutputCandidate)
        XCTAssertTrue(switchOff.shouldAllowCreate)
        XCTAssertFalse(switchOff.isPDFOutputCandidate)
    }

    func testNonPDFAndUnprotectedPathsAreAllowed() {
        let active = engine(mode: .enforce)
        let text = active.evaluatePrintToPDFCreate(
            process: process(),
            destinationPath: "/Users/alice/Documents/report.txt"
        )
        let libraryPDF = active.evaluatePrintToPDFCreate(
            process: process(),
            destinationPath: "/Users/alice/Library/Caches/report.pdf"
        )

        XCTAssertTrue(text.shouldAllowCreate)
        XCTAssertFalse(text.isPDFOutputCandidate)
        XCTAssertTrue(libraryPDF.shouldAllowCreate)
        XCTAssertFalse(libraryPDF.isPDFOutputCandidate)
    }

    func testBrowserDownloadStagingPathsRemainAllowed() {
        let chrome = process(
            signingId: "com.google.Chrome",
            teamId: "EQHXZ8M8AV",
            executablePath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        )
        let decision = engine(mode: .enforce).evaluatePrintToPDFCreate(
            process: chrome,
            destinationPath: "/Users/alice/Downloads/downloaded.pdf.crdownload"
        )

        XCTAssertTrue(decision.shouldAllowCreate)
        XCTAssertFalse(decision.isPDFOutputCandidate)
        XCTAssertEqual(decision.decisionString, "allowed")
    }

    func testBrowserDirectPDFOutputCannotBypassControl() {
        let safari = process(
            signingId: "com.apple.Safari",
            teamId: nil,
            isPlatformBinary: true,
            executablePath: "/Applications/Safari.app/Contents/MacOS/Safari"
        )
        let decision = engine(mode: .enforce).evaluatePrintToPDFCreate(
            process: safari,
            destinationPath: "/Users/alice/Documents/printed-page.pdf"
        )

        XCTAssertFalse(decision.shouldAllowCreate)
        XCTAssertTrue(decision.isPDFOutputCandidate)
        XCTAssertEqual(decision.decisionString, "blocked")
    }

    func testCriticalAndAuthenticVeloxProcessesRemainAllowed() {
        let launchd = process(
            signingId: "com.apple.launchd",
            teamId: nil,
            isPlatformBinary: true,
            executablePath: "/sbin/launchd"
        )
        let velox = process(
            signingId: "co.velox.macdlp.endpointsecurity",
            teamId: SecurityGuardian.expectedVeloxTeamID,
            executablePath: "/Applications/VeloxMacDLP.app/Contents/Library/SystemExtensions/co.velox.macdlp.endpointsecurity.systemextension/Contents/MacOS/co.velox.macdlp.endpointsecurity"
        )
        let active = engine(mode: .enforce)

        XCTAssertTrue(active.evaluatePrintToPDFCreate(
            process: launchd,
            destinationPath: "/Users/alice/Documents/system.pdf"
        ).shouldAllowCreate)
        XCTAssertTrue(active.evaluatePrintToPDFCreate(
            process: velox,
            destinationPath: "/Users/alice/Documents/velox.pdf"
        ).shouldAllowCreate)
    }
}
