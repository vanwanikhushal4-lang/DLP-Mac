import XCTest
@testable import VeloxCore

final class EventLoggerTests: XCTestCase {
    var tempDirectory: URL!
    var logURL: URL!

    override func setUp() {
        super.setUp()
        tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try! FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        logURL = tempDirectory.appendingPathComponent("events.jsonl")
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempDirectory)
        super.tearDown()
    }

    func testLogEventSchemaMatchesSpecification() throws {
        let logger = EventLogger(logFilePath: logURL.path)

        let event = ExecutionEvent(
            timestamp: "2026-09-04T14:40:00.000Z",
            eventId: "3c983d5a-1b42-4f01-9a74-9844f2ef3a61",
            module: "application-control",
            action: "exec",
            decision: "blocked",
            ruleId: "block-calculator",
            policyVersion: 1,
            executablePath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator",
            signingId: "com.apple.calculator",
            teamId: nil,
            pid: 1234,
            parentPid: 1200,
            uid: 501,
            decisionLatencyMicros: 450,
            resourcePath: "/Users/alice/Documents/report.pdf",
            destinationPath: "/Volumes/CLIENT_USB/report.pdf"
        )

        logger.logEventSync(event)
        logger.flushSync()

        let logContent = try String(contentsOf: logURL, encoding: .utf8)
        let lines = logContent.split(separator: "\n").map(String.init)
        XCTAssertEqual(lines.count, 1)

        let parsed = try JSONSerialization.jsonObject(with: lines[0].data(using: .utf8)!) as! [String: Any]
        XCTAssertEqual(parsed["timestamp"] as? String, "2026-09-04T14:40:00.000Z")
        XCTAssertEqual(parsed["eventId"] as? String, "3c983d5a-1b42-4f01-9a74-9844f2ef3a61")
        XCTAssertEqual(parsed["module"] as? String, "application-control")
        XCTAssertEqual(parsed["action"] as? String, "exec")
        XCTAssertEqual(parsed["decision"] as? String, "blocked")
        XCTAssertEqual(parsed["ruleId"] as? String, "block-calculator")
        XCTAssertEqual(parsed["policyVersion"] as? Int, 1)
        XCTAssertEqual(parsed["executablePath"] as? String, "/System/Applications/Calculator.app/Contents/MacOS/Calculator")
        XCTAssertEqual(parsed["signingId"] as? String, "com.apple.calculator")
        XCTAssertNil(parsed["teamId"] as? String)
        XCTAssertEqual(parsed["pid"] as? Int, 1234)
        XCTAssertEqual(parsed["parentPid"] as? Int, 1200)
        XCTAssertEqual(parsed["uid"] as? Int, 501)
        XCTAssertEqual(parsed["decisionLatencyMicros"] as? Int, 450)
        XCTAssertEqual(parsed["resourcePath"] as? String, "/Users/alice/Documents/report.pdf")
        XCTAssertEqual(parsed["destinationPath"] as? String, "/Volumes/CLIENT_USB/report.pdf")
    }

    func testOneHundredConsecutiveConcurrentLogWrites() throws {
        let logger = EventLogger(logFilePath: logURL.path)
        let group = DispatchGroup()
        let queue = DispatchQueue(label: "test.concurrent.writers", attributes: .concurrent)

        let count = 100
        for i in 1...count {
            group.enter()
            queue.async {
                let ev = ExecutionEvent(
                    timestamp: nil,
                    eventId: UUID().uuidString,
                    module: "application-control",
                    action: "exec",
                    decision: (i % 2 == 0) ? "blocked" : "allowed",
                    ruleId: (i % 2 == 0) ? "block-calculator" : nil,
                    policyVersion: 1,
                    executablePath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator",
                    signingId: "com.apple.calculator",
                    teamId: nil,
                    pid: Int32(2000 + i),
                    parentPid: 1000,
                    uid: 501,
                    decisionLatencyMicros: UInt64(i * 10)
                )
                logger.logEventAsync(ev)
                group.leave()
            }
        }

        let waitResult = group.wait(timeout: .now() + 5.0)
        XCTAssertEqual(waitResult, .success)

        logger.flushSync()

        let content = try String(contentsOf: logURL, encoding: .utf8)
        let lines = content.components(separatedBy: "\n").filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
        XCTAssertEqual(lines.count, 100, "Must record exactly 100 log lines without dropping any events")

        for (idx, line) in lines.enumerated() {
            guard let data = line.data(using: .utf8),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                XCTFail("Line \(idx) is not valid JSON: \(line)")
                continue
            }
            XCTAssertEqual(obj["module"] as? String, "application-control")
            XCTAssertEqual(obj["action"] as? String, "exec")
        }
    }
}
