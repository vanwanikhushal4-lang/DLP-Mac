import AppKit
import CoreGraphics
import CryptoKit
import Foundation
import ImageIO
import PDFKit
import UniformTypeIdentifiers
import Vision
import VeloxCore

struct OCRScanReport: Codable, Sendable {
    let ok: Bool
    let fileName: String
    let fileType: String
    let contentHashPrefix: String
    let source: String
    let decision: String
    let matches: [OCRRuleMatchSummary]
    let recognizedCharacterCount: Int
    let pageCount: Int
    let averageConfidence: Double
    let usedOCR: Bool
    let cacheHit: Bool
    let durationMillis: Int
    let message: String?
}

enum OCRServiceError: Error, LocalizedError {
    case inaccessibleFile
    case unsupportedFileType
    case oversizedFile(Int)
    case tooManyPDFPages(Int)
    case unreadableImage
    case unreadablePDF
    case noRecognizableContent

    var errorDescription: String? {
        switch self {
        case .inaccessibleFile:
            return "The selected file is not a readable regular file."
        case .unsupportedFileType:
            return "Content classification supports images, PDFs, and plain-text documents."
        case .oversizedFile(let limit):
            return "The selected file exceeds the configured \(limit) MB OCR limit."
        case .tooManyPDFPages(let limit):
            return "The PDF exceeds the configured \(limit)-page OCR limit."
        case .unreadableImage:
            return "The image could not be decoded."
        case .unreadablePDF:
            return "The PDF could not be opened."
        case .noRecognizableContent:
            return "No readable text or OCR-compatible image content was found."
        }
    }
}

private struct OCRTextSegment: Sendable {
    let text: String
    let confidence: Double
}

private final class OCRExtractedDocument: @unchecked Sendable {
    let text: String
    let characterCount: Int
    let pageCount: Int
    let averageConfidence: Double
    let usedOCR: Bool

    init(segments: [OCRTextSegment], pageCount: Int, usedOCR: Bool) {
        self.text = segments.map(\.text).joined(separator: "\n")
        self.characterCount = segments.reduce(0) { $0 + $1.text.count }
        self.pageCount = pageCount
        self.averageConfidence = segments.isEmpty
            ? 0
            : segments.reduce(0) { $0 + $1.confidence } / Double(segments.count)
        self.usedOCR = usedOCR
    }
}

/// Performs bounded, on-device OCR away from Endpoint Security authorization
/// callbacks. Extracted text is held only in memory; cache keys and scan reports
/// contain a short content-hash prefix rather than source text.
final class OCRService: @unchecked Sendable {
    private let queue = DispatchQueue(
        label: "co.velox.macdlp.ocr",
        qos: .userInitiated,
        attributes: .concurrent
    )
    private let cache = NSCache<NSString, OCRExtractedDocument>()

    init() {
        cache.countLimit = 128
        cache.totalCostLimit = 64 * 1024 * 1024
    }

    func analyze(
        url: URL,
        config: OCRControlConfig,
        mode: PolicyMode? = nil,
        source: String,
        completion: @escaping @Sendable (Result<OCRScanReport, Error>) -> Void
    ) {
        queue.async { [weak self] in
            guard let self else { return }
            do {
                completion(.success(try self.analyzeSync(
                    url: url,
                    config: config,
                    mode: mode,
                    source: source
                )))
            } catch {
                completion(.failure(error))
            }
        }
    }

    func analyzeSync(
        url: URL,
        config: OCRControlConfig,
        mode: PolicyMode?,
        source: String
    ) throws -> OCRScanReport {
        let started = DispatchTime.now().uptimeNanoseconds
        let values = try url.resourceValues(forKeys: [
            .isRegularFileKey,
            .isReadableKey,
            .fileSizeKey,
            .contentTypeKey
        ])
        guard values.isRegularFile == true, values.isReadable != false else {
            throw OCRServiceError.inaccessibleFile
        }
        let fileSize = values.fileSize ?? 0
        guard fileSize <= config.maxFileSizeMB * 1_048_576 else {
            throw OCRServiceError.oversizedFile(config.maxFileSizeMB)
        }

        let contentType = values.contentType
            ?? UTType(filenameExtension: url.pathExtension)
        guard let contentType,
              contentType.conforms(to: .image) ||
              contentType.conforms(to: .pdf) ||
              contentType.conforms(to: .text) else {
            throw OCRServiceError.unsupportedFileType
        }

        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        let fullHash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        let languageKey = config.recognitionLanguages.joined(separator: ",")
        let cacheKey = "v1:\(fullHash):\(languageKey):\(config.minimumConfidence)" as NSString

        let extracted: OCRExtractedDocument
        let cacheHit: Bool
        if let cached = cache.object(forKey: cacheKey) {
            extracted = cached
            cacheHit = true
        } else {
            if contentType.conforms(to: .pdf) {
                extracted = try extractPDF(url: url, config: config)
            } else if contentType.conforms(to: .image) {
                extracted = try extractImage(url: url, config: config)
            } else {
                extracted = try extractPlainText(data: data)
            }
            cache.setObject(extracted, forKey: cacheKey, cost: min(data.count, 8 * 1024 * 1024))
            cacheHit = false
        }

        guard extracted.characterCount > 0 else {
            throw OCRServiceError.noRecognizableContent
        }
        let verdict = OCRClassifier.evaluate(text: extracted.text, config: config, mode: mode)
        let durationMillis = Int(
            (DispatchTime.now().uptimeNanoseconds - started) / 1_000_000
        )
        return OCRScanReport(
            ok: true,
            fileName: url.lastPathComponent,
            fileType: contentType.identifier,
            contentHashPrefix: String(fullHash.prefix(12)),
            source: source,
            decision: verdict.decision,
            matches: verdict.matches,
            recognizedCharacterCount: extracted.characterCount,
            pageCount: extracted.pageCount,
            averageConfidence: extracted.averageConfidence,
            usedOCR: extracted.usedOCR,
            cacheHit: cacheHit,
            durationMillis: durationMillis,
            message: verdict.matches.isEmpty
                ? "No configured sensitive-data rule matched."
                : "Sensitive text matched \(verdict.matches.count) configured rule\(verdict.matches.count == 1 ? "" : "s")."
        )
    }

    private func extractImage(url: URL, config: OCRControlConfig) throws -> OCRExtractedDocument {
        guard let source = CGImageSourceCreateWithURL(url as CFURL, nil) else {
            throw OCRServiceError.unreadableImage
        }
        let frameCount = CGImageSourceGetCount(source)
        guard frameCount > 0 else { throw OCRServiceError.unreadableImage }

        var segments: [OCRTextSegment] = []
        for index in 0..<frameCount {
            guard let image = CGImageSourceCreateImageAtIndex(source, index, nil) else { continue }
            segments.append(contentsOf: try recognize(image: image, config: config))
        }
        return OCRExtractedDocument(
            segments: segments,
            pageCount: frameCount,
            usedOCR: true
        )
    }

    private func extractPlainText(data: Data) throws -> OCRExtractedDocument {
        let encodings: [String.Encoding] = [.utf8, .utf16, .unicode, .ascii]
        guard let text = encodings.lazy.compactMap({ String(data: data, encoding: $0) }).first else {
            throw OCRServiceError.noRecognizableContent
        }
        let bounded = String(text.prefix(OCRClassifier.maximumInputCharacters))
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !bounded.isEmpty else { throw OCRServiceError.noRecognizableContent }
        return OCRExtractedDocument(
            segments: [OCRTextSegment(text: bounded, confidence: 1)],
            pageCount: 1,
            usedOCR: false
        )
    }

    private func extractPDF(url: URL, config: OCRControlConfig) throws -> OCRExtractedDocument {
        guard let document = PDFDocument(url: url) else {
            throw OCRServiceError.unreadablePDF
        }
        guard document.pageCount <= config.maxPDFPages else {
            throw OCRServiceError.tooManyPDFPages(config.maxPDFPages)
        }

        var segments: [OCRTextSegment] = []
        var usedOCR = false
        for index in 0..<document.pageCount {
            guard let page = document.page(at: index) else { continue }
            let embeddedText = page.string?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if !embeddedText.isEmpty {
                segments.append(OCRTextSegment(text: embeddedText, confidence: 1))
                continue
            }

            let bounds = page.bounds(for: .mediaBox)
            let longestEdge = max(bounds.width, bounds.height)
            let scale = min(4, max(1, 2400 / max(longestEdge, 1)))
            let size = NSSize(
                width: max(1, bounds.width * scale),
                height: max(1, bounds.height * scale)
            )
            let thumbnail = page.thumbnail(of: size, for: .mediaBox)
            var proposedRect = NSRect(origin: .zero, size: thumbnail.size)
            guard let image = thumbnail.cgImage(
                forProposedRect: &proposedRect,
                context: nil,
                hints: nil
            ) else { continue }
            segments.append(contentsOf: try recognize(image: image, config: config))
            usedOCR = true
        }

        return OCRExtractedDocument(
            segments: segments,
            pageCount: document.pageCount,
            usedOCR: usedOCR
        )
    }

    private func recognize(
        image: CGImage,
        config: OCRControlConfig
    ) throws -> [OCRTextSegment] {
        let request = VNRecognizeTextRequest()
        request.recognitionLevel = .accurate
        request.usesLanguageCorrection = true
        request.recognitionLanguages = config.recognitionLanguages

        let handler = VNImageRequestHandler(cgImage: image)
        try handler.perform([request])
        let observations = request.results ?? []
        return observations.compactMap { observation in
            guard let candidate = observation.topCandidates(1).first,
                  Double(candidate.confidence) >= config.minimumConfidence else {
                return nil
            }
            let text = candidate.string.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !text.isEmpty else { return nil }
            return OCRTextSegment(text: text, confidence: Double(candidate.confidence))
        }
    }
}
