import Foundation

public struct OCRRuleMatchSummary: Codable, Sendable, Equatable {
    public let ruleId: String
    public let name: String
    public let classification: String
    public let matchCount: Int

    public init(ruleId: String, name: String, classification: String, matchCount: Int) {
        self.ruleId = ruleId
        self.name = name
        self.classification = classification
        self.matchCount = matchCount
    }
}

public struct OCRClassificationVerdict: Codable, Sendable, Equatable {
    public let decision: String
    public let matches: [OCRRuleMatchSummary]

    public var containsSensitiveContent: Bool { !matches.isEmpty }

    public init(decision: String, matches: [OCRRuleMatchSummary]) {
        self.decision = decision
        self.matches = matches
    }
}

/// Privacy-safe policy evaluation for text extracted by OCR or PDFKit.
/// The returned verdict never includes the matched source text.
public enum OCRClassifier {
    public static let maximumInputCharacters = 1_000_000

    public static func evaluate(
        text: String,
        config: OCRControlConfig,
        mode: PolicyMode? = nil
    ) -> OCRClassificationVerdict {
        let boundedText = String(text.prefix(maximumInputCharacters))
        let activeMode = mode ?? config.mode
        let matches = config.rules.compactMap { rule -> OCRRuleMatchSummary? in
            let count = matchCount(for: rule, in: boundedText)
            guard count >= rule.minimumMatches else { return nil }
            return OCRRuleMatchSummary(
                ruleId: rule.ruleId,
                name: rule.name,
                classification: rule.classification,
                matchCount: count
            )
        }

        let decision: String
        if matches.isEmpty || activeMode == .disabled {
            decision = "allowed"
        } else if activeMode == .auditOnly {
            decision = "would-block"
        } else {
            decision = "blocked"
        }
        return OCRClassificationVerdict(decision: decision, matches: matches)
    }

    private static func matchCount(for rule: OCRClassificationRule, in text: String) -> Int {
        switch rule.type {
        case .keyword:
            let foldedText = text.folding(
                options: [.caseInsensitive, .diacriticInsensitive],
                locale: Locale(identifier: "en_US_POSIX")
            )
            return rule.keywords.reduce(into: 0) { result, keyword in
                let foldedKeyword = keyword.folding(
                    options: [.caseInsensitive, .diacriticInsensitive],
                    locale: Locale(identifier: "en_US_POSIX")
                )
                var searchRange = foldedText.startIndex..<foldedText.endIndex
                while let range = foldedText.range(of: foldedKeyword, options: [], range: searchRange) {
                    result += 1
                    searchRange = range.upperBound..<foldedText.endIndex
                }
            }
        case .regularExpression:
            guard let pattern = rule.pattern,
                  let expression = try? NSRegularExpression(
                      pattern: pattern,
                      options: [.caseInsensitive]
                  ) else { return 0 }
            return expression.numberOfMatches(
                in: text,
                range: NSRange(text.startIndex..<text.endIndex, in: text)
            )
        case .creditCard:
            return candidates(
                in: text,
                pattern: #"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"#
            ).filter { isValidPaymentCard($0) }.count
        case .indianPAN:
            return candidates(
                in: text.uppercased(),
                pattern: #"(?<![A-Z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Z0-9])"#
            ).count
        case .aadhaar:
            return candidates(
                in: text,
                pattern: #"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)"#
            ).filter { isValidAadhaar($0) }.count
        }
    }

    private static func candidates(in text: String, pattern: String) -> [String] {
        guard let expression = try? NSRegularExpression(pattern: pattern) else { return [] }
        let nsText = text as NSString
        return expression.matches(
            in: text,
            range: NSRange(location: 0, length: nsText.length)
        ).map { nsText.substring(with: $0.range) }
    }

    private static func digitsOnly(_ value: String) -> [Int] {
        value.compactMap { $0.wholeNumberValue }
    }

    private static func isValidPaymentCard(_ value: String) -> Bool {
        let digits = digitsOnly(value)
        guard (13...19).contains(digits.count), Set(digits).count > 1 else { return false }
        var total = 0
        for (offset, digit) in digits.reversed().enumerated() {
            if offset.isMultiple(of: 2) {
                total += digit
            } else {
                let doubled = digit * 2
                total += doubled > 9 ? doubled - 9 : doubled
            }
        }
        return total.isMultiple(of: 10)
    }

    /// Verhoeff validation required for a syntactically valid 12-digit Aadhaar number.
    private static func isValidAadhaar(_ value: String) -> Bool {
        let digits = digitsOnly(value)
        guard digits.count == 12, let first = digits.first, (2...9).contains(first) else {
            return false
        }
        let multiplication = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
            [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
            [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
            [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
            [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
            [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
            [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
            [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
            [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
        ]
        let permutation = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
            [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
            [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
            [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
            [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
            [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
            [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
        ]

        var checksum = 0
        for (index, digit) in digits.reversed().enumerated() {
            checksum = multiplication[checksum][permutation[index % 8][digit]]
        }
        return checksum == 0
    }
}
