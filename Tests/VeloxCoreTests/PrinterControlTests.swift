import XCTest
@testable import VeloxCore

final class PrinterControlTests: XCTestCase {
    func testLegacyPolicyDefaultsPrinterControlToDisabled() throws {
        let json = """
        {
          "policyVersion": 1,
          "applicationControl": { "mode": "enforce" }
        }
        """

        let policy = try VeloxPolicy.decodeStrict(from: Data(json.utf8))
        XCTAssertEqual(policy.printerControl.mode, .disabled)
        XCTAssertTrue(policy.printerControl.blockAllPrinters)
    }

    func testPrinterPolicyStrictDecodingAndUnknownPropertyRejection() throws {
        let json = """
        {
          "policyVersion": 44,
          "applicationControl": { "mode": "enforce" },
          "printerControl": {
            "mode": "audit-only",
            "blockAllPrinters": true
          }
        }
        """

        let policy = try VeloxPolicy.decodeStrict(from: Data(json.utf8))
        XCTAssertEqual(policy.printerControl.mode, .auditOnly)
        XCTAssertTrue(policy.printerControl.blockAllPrinters)

        let invalid = json.replacingOccurrences(
            of: "\"blockAllPrinters\": true",
            with: "\"allowBypass\": true, \"blockAllPrinters\": true"
        )
        XCTAssertThrowsError(try VeloxPolicy.decodeStrict(from: Data(invalid.utf8))) { error in
            guard case PolicyValidationError.unknownProperty = error else {
                XCTFail("Expected unknownProperty, got \(error)")
                return
            }
        }
    }

    func testPrinterQueueParserCombinesEnabledAndAcceptingState() {
        let printers = """
        printer Office-HP is idle. enabled since Sat 06 Sep 2026 10:00:00 AM IST
        printer Finance-Laser disabled since Sat 06 Sep 2026 10:01:00 AM IST -
        \tPaused by administrator
        """
        let accepting = """
        Office-HP accepting requests since Sat 06 Sep 2026 10:00:00 AM IST
        Finance-Laser not accepting requests since Sat 06 Sep 2026 10:01:00 AM IST -
        \tPaused by administrator
        """

        XCTAssertEqual(
            PrinterQueueParser.queues(
                printersOutput: printers,
                acceptingOutput: accepting
            ),
            [
                PrinterQueueSnapshot(
                    name: "Finance-Laser",
                    isEnabled: false,
                    isAcceptingJobs: false
                ),
                PrinterQueueSnapshot(
                    name: "Office-HP",
                    isEnabled: true,
                    isAcceptingJobs: true
                )
            ]
        )
    }

    func testPrinterJobParserHandlesHyphenatedQueueNamesAndRejectsMalformedLines() {
        let output = """
        Office-HP-127 alice 2048 Sat 06 Sep 2026 10:02:00 AM IST
        Finance-Laser-9 bob 8192 Sat 06 Sep 2026 10:03:00 AM IST
        malformed-job-id alice 1 now
        bad/name-12 alice 1 now
        """

        XCTAssertEqual(
            PrinterQueueParser.jobs(from: output),
            [
                PrinterJobSnapshot(identifier: "Office-HP-127", queueName: "Office-HP"),
                PrinterJobSnapshot(identifier: "Finance-Laser-9", queueName: "Finance-Laser")
            ]
        )
    }

    func testNoDestinationsMessageIsRecognizedCaseInsensitively() {
        XCTAssertTrue(PrinterQueueParser.isNoDestinationsMessage("lpstat: No destinations added."))
        XCTAssertTrue(PrinterQueueParser.isNoDestinationsMessage("NO DESTINATIONS ADDED"))
        XCTAssertFalse(PrinterQueueParser.isNoDestinationsMessage("scheduler is running"))
    }
}
