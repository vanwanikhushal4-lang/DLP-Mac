import AppKit
import Foundation
import XCTest
import VeloxCore

final class OCRServiceTests: XCTestCase, @unchecked Sendable {
    @MainActor
    func testVisionRecognizesAndClassifiesGeneratedImage() async throws {
        let image = NSImage(size: NSSize(width: 1400, height: 500))
        image.lockFocus()
        NSColor.white.setFill()
        NSRect(x: 0, y: 0, width: 1400, height: 500).fill()
        let attributes: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 68, weight: .bold),
            .foregroundColor: NSColor.black
        ]
        NSString(string: "CONFIDENTIAL\n4111 1111 1111 1111").draw(
            in: NSRect(x: 80, y: 120, width: 1240, height: 260),
            withAttributes: attributes
        )
        image.unlockFocus()

        let png = try XCTUnwrap(
            image.tiffRepresentation
                .flatMap(NSBitmapImageRep.init(data:))?
                .representation(using: .png, properties: [:])
        )
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("velox-ocr-smoke-\(UUID().uuidString).png")
        try png.write(to: url, options: .atomic)
        defer { try? FileManager.default.removeItem(at: url) }

        let service = OCRService()
        let report: OCRScanReport = try await withCheckedThrowingContinuation { continuation in
            service.analyze(
                url: url,
                config: OCRControlConfig(mode: .enforce, minimumConfidence: 0.35),
                source: "manual"
            ) { continuation.resume(with: $0) }
        }

        XCTAssertEqual(report.decision, "blocked")
        XCTAssertTrue(report.usedOCR)
        XCTAssertGreaterThan(report.recognizedCharacterCount, 10)
        XCTAssertTrue(report.matches.contains { $0.ruleId == "ocr-confidential-keywords" })
        XCTAssertTrue(report.matches.contains { $0.ruleId == "ocr-payment-card" })
    }
}
