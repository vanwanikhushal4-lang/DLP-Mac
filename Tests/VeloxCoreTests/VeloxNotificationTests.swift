import XCTest
@testable import VeloxCore

final class VeloxNotificationTests: XCTestCase {
    func testEgressClassificationFailureNotificationExplainsStrictHold() {
        let formatted = VeloxNotificationFormatter.format(
            module: "ocr-content-classification",
            action: "egress-scan-failed",
            target: "/Users/alice/Documents/archive.zip",
            detail: "unsupported-file-type"
        )

        XCTAssertEqual(formatted.title, "Blocked by Velox DLP")
        XCTAssertEqual(formatted.subtitle, "File Classification Failed")
        XCTAssertTrue(formatted.body.contains("archive.zip"))
        XCTAssertTrue(formatted.body.contains("unsupported file type"))
    }

    func testClassifiedEgressNotificationsDoNotExposeContent() {
        let scanning = VeloxNotificationFormatter.format(
            module: "web-upload-control",
            action: "classified-content-scan-required",
            target: "/Users/alice/Documents/id.png",
            detail: ""
        )
        XCTAssertEqual(scanning.subtitle, "File Classification Required")
        XCTAssertTrue(scanning.body.contains("Retry"))

        let blocked = VeloxNotificationFormatter.format(
            module: "usb-storage-control",
            action: "classified-content-copy",
            target: "/Users/alice/Documents/id.png",
            detail: "Indian Identity Data"
        )
        XCTAssertEqual(blocked.subtitle, "Classified File Transfer Blocked")
        XCTAssertTrue(blocked.body.contains("Indian Identity Data"))
        XCTAssertFalse(blocked.body.contains("2345"))
    }


    func testApplicationControlNotificationFormatting() {
        let formatted = VeloxNotificationFormatter.format(
            module: "application-control",
            action: "exec",
            target: "/System/Applications/Calculator.app/Contents/MacOS/Calculator",
            detail: "com.apple.calculator"
        )

        XCTAssertEqual(formatted.title, "Blocked by Velox DLP")
        XCTAssertEqual(formatted.subtitle, "Application Blocked")
        XCTAssertEqual(formatted.body, "'Calculator' was blocked from launching by security policy.")
    }

    func testWebUploadNotificationFormatting() {
        let formatted = VeloxNotificationFormatter.format(
            module: "web-upload-control",
            action: "browser-file-open",
            target: "/Users/alice/Documents/financial_q4.pdf",
            detail: "com.google.chrome"
        )

        XCTAssertEqual(formatted.title, "Blocked by Velox DLP")
        XCTAssertEqual(formatted.subtitle, "Web Upload Blocked")
        XCTAssertEqual(formatted.body, "Uploading 'financial_q4.pdf' to Google Chrome was blocked by security policy.")
    }

    func testClipboardPasteNotificationFormatting() {
        let formatted = VeloxNotificationFormatter.format(
            module: "web-upload-control",
            action: "clipboard-paste",
            target: "passwords.txt, api_keys.env",
            detail: "org.mozilla.firefox"
        )

        XCTAssertEqual(formatted.title, "Blocked by Velox DLP")
        XCTAssertEqual(formatted.subtitle, "Web Upload Blocked")
        XCTAssertEqual(formatted.body, "Pasting protected file 'passwords.txt (and 1 other files)' into Firefox was blocked.")
    }

    func testClipboardControlNotificationFormatting() {
        let formatted = VeloxNotificationFormatter.format(
            module: "clipboard-control",
            action: "copy",
            target: "formatted-text, text · 1 item",
            detail: "Notes"
        )

        XCTAssertEqual(formatted.title, "Blocked by Velox DLP")
        XCTAssertEqual(formatted.subtitle, "Clipboard Copy Blocked")
        XCTAssertEqual(
            formatted.body,
            "Copying formatted-text, text · 1 item from Notes was blocked by security policy."
        )
    }

    func testUSBStorageNotificationFormatting() {
        let formatted = VeloxNotificationFormatter.format(
            module: "usb-storage-control",
            action: "mount",
            target: "/dev/disk3s1 -> /Volumes/BACKUP_DRIVE (msdos)",
            detail: ""
        )

        XCTAssertEqual(formatted.title, "Blocked by Velox DLP")
        XCTAssertEqual(formatted.subtitle, "USB Storage Blocked")
        XCTAssertEqual(formatted.body, "External storage 'BACKUP_DRIVE' was blocked from mounting.")
    }

    func testUSBEncryptionNotificationFormatting() {
        let formatted = VeloxNotificationFormatter.format(
            module: "usb-encryption-control",
            action: "plaintext-create",
            target: "/Volumes/CLIENT_USB",
            detail: ""
        )

        XCTAssertEqual(formatted.title, "Blocked by Velox DLP")
        XCTAssertEqual(formatted.subtitle, "USB Encryption Required")
        XCTAssertEqual(
            formatted.body,
            "A plaintext copy to 'CLIENT_USB' was blocked. Copy into Velox Secure USB instead."
        )
    }

    func testOpticalAndDiskImageNotificationFormatting() {
        let diskImage = VeloxNotificationFormatter.format(
            module: "optical-disk-image-control",
            action: "disk-image-mount",
            target: "/dev/disk8s1 -> /Volumes/Installer (apfs)",
            detail: "com.apple.diskarbitrationd"
        )
        XCTAssertEqual(diskImage.title, "Blocked by Velox DLP")
        XCTAssertEqual(diskImage.subtitle, "Disk Image Blocked")
        XCTAssertEqual(
            diskImage.body,
            "Disk image 'Installer' was blocked from mounting by security policy."
        )

        let optical = VeloxNotificationFormatter.format(
            module: "optical-disk-image-control",
            action: "optical-media-mount",
            target: "/dev/disk9 -> /Volumes/ARCHIVE_DVD (udf)",
            detail: "com.apple.diskarbitrationd"
        )
        XCTAssertEqual(optical.subtitle, "Optical Media Blocked")
        XCTAssertEqual(
            optical.body,
            "Optical media 'ARCHIVE_DVD' was blocked from mounting by security policy."
        )
    }

    func testPrinterControlNotificationFormatting() {
        let formatted = VeloxNotificationFormatter.format(
            module: "printer-control",
            action: "queue-disabled",
            target: "Office-HP",
            detail: "com.apple.cupsd"
        )

        XCTAssertEqual(formatted.title, "Blocked by Velox DLP")
        XCTAssertEqual(formatted.subtitle, "Printing Blocked")
        XCTAssertEqual(
            formatted.body,
            "Printing to printer 'Office-HP' was blocked by security policy."
        )
    }

    func testPrintToPDFNotificationFormatting() {
        let formatted = VeloxNotificationFormatter.format(
            module: "print-to-pdf-control",
            action: "pdf-file-create",
            target: "/Users/alice/Documents/board-report.pdf",
            detail: "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word"
        )

        XCTAssertEqual(formatted.title, "Blocked by Velox DLP")
        XCTAssertEqual(formatted.subtitle, "PDF File Output Blocked")
        XCTAssertEqual(
            formatted.body,
            "Creating 'board-report.pdf' from Microsoft Word was blocked by security policy."
        )
    }

    func testOCRNotificationFormattingDoesNotExposeRecognizedText() {
        let formatted = VeloxNotificationFormatter.format(
            module: "ocr-content-classification",
            action: "screenshot-scan",
            target: "public.png",
            detail: "Payment Card Data, Confidential Document"
        )

        XCTAssertEqual(formatted.title, "Blocked by Velox DLP")
        XCTAssertEqual(formatted.subtitle, "Sensitive Screenshot Blocked")
        XCTAssertEqual(
            formatted.body,
            "Velox DLP detected Payment Card Data, Confidential Document and secured the screenshot."
        )
        XCTAssertFalse(formatted.body.contains("public.png"))
    }

    func testNearbyTransferNotificationFormatting() {
        let airDrop = VeloxNotificationFormatter.format(
            module: "nearby-transfer-control",
            action: "airdrop-file-open",
            target: "/Users/alice/Documents/strategy.pdf",
            detail: "com.apple.finder.Open-AirDrop"
        )
        XCTAssertEqual(airDrop.title, "Blocked by Velox DLP")
        XCTAssertEqual(airDrop.subtitle, "Nearby Transfer Blocked")
        XCTAssertEqual(
            airDrop.body,
            "Sending 'strategy.pdf' through AirDrop was blocked by security policy."
        )

        let appleSharing = VeloxNotificationFormatter.format(
            module: "nearby-transfer-control",
            action: "apple-sharing-file-open",
            target: "/Users/alice/Desktop/customer.csv",
            detail: "com.apple.sharingd"
        )
        XCTAssertEqual(
            appleSharing.body,
            "Sending 'customer.csv' through Apple nearby sharing was blocked by security policy."
        )

        let bluetooth = VeloxNotificationFormatter.format(
            module: "nearby-transfer-control",
            action: "bluetooth-file-open",
            target: "/Users/alice/Downloads/source.zip",
            detail: "com.apple.BluetoothFileExchange"
        )
        XCTAssertEqual(
            bluetooth.body,
            "Sending 'source.zip' through Bluetooth file transfer was blocked by security policy."
        )
    }

    func testNotificationDebouncerSuppressesDuplicateEvents() {
        let debouncer = VeloxNotificationDebouncer(interval: 2.0)
        let key = "application-control:/System/Applications/Calculator.app"
        let t0 = Date()

        // First delivery should be allowed
        XCTAssertTrue(debouncer.shouldDeliver(key: key, now: t0))

        // Delivery 0.5s later should be suppressed
        let t1 = t0.addingTimeInterval(0.5)
        XCTAssertFalse(debouncer.shouldDeliver(key: key, now: t1))

        // Delivery 1.9s later should still be suppressed
        let t2 = t0.addingTimeInterval(1.9)
        XCTAssertFalse(debouncer.shouldDeliver(key: key, now: t2))

        // Delivery 2.1s later should be allowed
        let t3 = t0.addingTimeInterval(2.1)
        XCTAssertTrue(debouncer.shouldDeliver(key: key, now: t3))

        // Different key should not be affected
        let otherKey = "usb-storage-control:/Volumes/USB"
        XCTAssertTrue(debouncer.shouldDeliver(key: otherKey, now: t1))
    }

    private final class EventBox: @unchecked Sendable {
        private let lock = NSLock()
        private var storedEvent: ExecutionEvent?

        func set(_ event: ExecutionEvent) {
            lock.lock()
            storedEvent = event
            lock.unlock()
        }

        func get() -> ExecutionEvent? {
            lock.lock()
            defer { lock.unlock() }
            return storedEvent
        }
    }

    func testEndpointSecurityServiceOnEventBlockedCallback() {
        let policy = VeloxPolicy(
            policyVersion: 1,
            applicationControl: ApplicationControlConfig(
                mode: .enforce,
                blockedApplications: [
                    ApplicationRule(
                        ruleId: "block-calc",
                        signingId: "com.apple.calculator"
                    )
                ]
            )
        )
        let policyEngine = PolicyEngine(policy: policy)
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(atPath: tempDir.path, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let logger = EventLogger(logFilePath: tempDir.appendingPathComponent("events.jsonl").path)
        let esService = EndpointSecurityService(
            policyEngine: policyEngine,
            logger: logger,
            healthPath: tempDir.appendingPathComponent("health.json").path
        )

        let box = EventBox()
        esService.onEventBlocked = { event in
            box.set(event)
        }

        XCTAssertNotNil(esService.onEventBlocked)

        let testEvent = ExecutionEvent(
            timestamp: nil,
            eventId: "test-id",
            module: "application-control",
            action: "exec",
            decision: "blocked",
            ruleId: "block-calc",
            policyVersion: 1,
            executablePath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator",
            signingId: "com.apple.calculator",
            teamId: nil,
            pid: 100,
            parentPid: 1,
            uid: 501,
            decisionLatencyMicros: 10,
            authResponseResult: "success"
        )
        esService.onEventBlocked?(testEvent)

        XCTAssertEqual(box.get()?.decision, "blocked")
        XCTAssertEqual(box.get()?.module, "application-control")
    }
}
