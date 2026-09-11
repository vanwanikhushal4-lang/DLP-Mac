import Foundation

public enum PolicyMode: String, Codable, Sendable, Equatable {
    case enforce
    case auditOnly = "audit-only"
    case disabled
}

public struct ApplicationRule: Codable, Sendable, Equatable {
    public let ruleId: String
    public let signingId: String?
    public let teamId: String?
    public let isPlatformBinary: Bool?
    public let cdhash: String?
    public let executablePath: String?
    public let executablePathPrefix: String?

    public init(
        ruleId: String,
        signingId: String? = nil,
        teamId: String? = nil,
        isPlatformBinary: Bool? = nil,
        cdhash: String? = nil,
        executablePath: String? = nil,
        executablePathPrefix: String? = nil
    ) {
        self.ruleId = ruleId
        self.signingId = signingId
        self.teamId = teamId
        self.isPlatformBinary = isPlatformBinary
        self.cdhash = cdhash?.lowercased()
        self.executablePath = executablePath
        self.executablePathPrefix = executablePathPrefix
    }

    public func validate(isAllowRule: Bool = false) throws {
        let trimmedRuleId = ruleId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedRuleId.isEmpty else {
            throw PolicyValidationError.emptyRuleId("Rule ID cannot be empty")
        }

        // Validate that matching values are not empty strings if provided
        if let s = signingId {
            guard !s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw PolicyValidationError.emptyCriterion("signingId in rule '\(ruleId)' cannot be empty")
            }
        }
        if let t = teamId {
            guard !t.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw PolicyValidationError.emptyCriterion("teamId in rule '\(ruleId)' cannot be empty")
            }
        }
        if let c = cdhash {
            let trimmed = c.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                throw PolicyValidationError.emptyCriterion("cdhash in rule '\(ruleId)' cannot be empty")
            }
            guard trimmed.count == 40 && trimmed.allSatisfy({ $0.isHexDigit }) else {
                throw PolicyValidationError.invalidCriterion("cdhash in rule '\(ruleId)' must be a 40-character hex string")
            }
        }
        if let p = executablePath {
            guard !p.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw PolicyValidationError.emptyCriterion("executablePath in rule '\(ruleId)' cannot be empty")
            }
            guard p.hasPrefix("/") else {
                throw PolicyValidationError.unsafePathPrefix("executablePath in rule '\(ruleId)' must be an absolute path starting with '/'")
            }
        }
        if let prefix = executablePathPrefix {
            let trimmedPrefix = prefix.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmedPrefix.isEmpty else {
                throw PolicyValidationError.emptyCriterion("executablePathPrefix in rule '\(ruleId)' cannot be empty")
            }
            guard trimmedPrefix != "/" else {
                throw PolicyValidationError.unsafePathPrefix("executablePathPrefix in rule '\(ruleId)' cannot be root '/' as it is dangerously broad")
            }
            guard trimmedPrefix.hasPrefix("/") else {
                throw PolicyValidationError.unsafePathPrefix("executablePathPrefix in rule '\(ruleId)' must be an absolute path prefix starting with '/'")
            }
        }

        let hasCriterion = signingId != nil ||
                           teamId != nil ||
                           isPlatformBinary != nil ||
                           cdhash != nil ||
                           executablePath != nil ||
                           executablePathPrefix != nil
        guard hasCriterion else {
            throw PolicyValidationError.missingCriterion("Rule '\(ruleId)' must specify at least one valid matching criterion")
        }

        if isAllowRule {
            // Require secure identity criteria: an allow rule based solely on signingId can be spoofed by ad-hoc binaries
            if signingId != nil {
                let hasSecureBinding = (teamId != nil) || (cdhash != nil) || (isPlatformBinary == true) || (executablePath != nil)
                guard hasSecureBinding else {
                    throw PolicyValidationError.insecureAllowRule("Allow rule '\(ruleId)' based solely on signingId is insecure. Allow rules must bind teamId, cdhash, isPlatformBinary, or exact executablePath to prevent ad-hoc spoofing.")
                }
            }
        }
    }
}

public struct ApplicationControlConfig: Codable, Sendable, Equatable {
    public let mode: PolicyMode
    public let blockedApplications: [ApplicationRule]
    public let allowedApplications: [ApplicationRule]

    public init(
        mode: PolicyMode,
        blockedApplications: [ApplicationRule] = [],
        allowedApplications: [ApplicationRule] = []
    ) {
        self.mode = mode
        self.blockedApplications = blockedApplications
        self.allowedApplications = allowedApplications
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.mode = try container.decode(PolicyMode.self, forKey: .mode)
        self.blockedApplications = try container.decodeIfPresent([ApplicationRule].self, forKey: .blockedApplications) ?? []
        self.allowedApplications = try container.decodeIfPresent([ApplicationRule].self, forKey: .allowedApplications) ?? []
    }
}

/// Prototype policy for one-way browser file-transfer control.
///
/// The Endpoint Security implementation intentionally protects only regular files
/// in well-known user content folders. Browser profile data under ~/Library is
/// never included, and write-only opens remain allowed so downloads can complete.
public struct WebUploadControlConfig: Codable, Sendable, Equatable {
    public static let defaultProtectedDirectoryNames = [
        "Desktop", "Documents", "Downloads", "Movies", "Music", "Pictures", "Public"
    ]

    public let mode: PolicyMode
    public let protectedDirectoryNames: [String]

    public init(
        mode: PolicyMode = .disabled,
        protectedDirectoryNames: [String] = WebUploadControlConfig.defaultProtectedDirectoryNames
    ) {
        self.mode = mode
        self.protectedDirectoryNames = protectedDirectoryNames
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.mode = try container.decode(PolicyMode.self, forKey: .mode)
        self.protectedDirectoryNames = try container.decodeIfPresent(
            [String].self,
            forKey: .protectedDirectoryNames
        ) ?? Self.defaultProtectedDirectoryNames
    }

    public func validate() throws {
        guard !protectedDirectoryNames.isEmpty else {
            throw PolicyValidationError.invalidCriterion(
                "webUploadControl.protectedDirectoryNames cannot be empty"
            )
        }

        var seen = Set<String>()
        for directoryName in protectedDirectoryNames {
            let trimmed = directoryName.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty,
                  trimmed != ".",
                  trimmed != "..",
                  !trimmed.contains("/") else {
                throw PolicyValidationError.invalidCriterion(
                    "Protected directory names must be single safe path components"
                )
            }
            guard seen.insert(trimmed.lowercased()).inserted else {
                throw PolicyValidationError.invalidCriterion(
                    "Duplicate protected directory name '\(trimmed)'"
                )
            }
        }
    }
}

/// Blocks native mail clients from reading files that Endpoint Discovery has
/// already classified. This is intentionally an endpoint file-access control:
/// macOS Endpoint Security does not expose recipients or a reliable Send event.
public struct EmailAttachmentControlConfig: Codable, Sendable, Equatable {
    public static let defaultMailClients: [ApplicationRule] = [
        ApplicationRule(
            ruleId: "email-apple-mail",
            signingId: "com.apple.mail",
            isPlatformBinary: true
        ),
        ApplicationRule(
            ruleId: "email-microsoft-outlook",
            signingId: "com.microsoft.Outlook",
            teamId: "UBF8T346G9"
        )
    ]

    public let mode: PolicyMode
    public let mailClients: [ApplicationRule]
    /// Empty means every active OCR classification is protected.
    public let protectedClassifications: [String]

    public init(
        mode: PolicyMode = .disabled,
        mailClients: [ApplicationRule] = EmailAttachmentControlConfig.defaultMailClients,
        protectedClassifications: [String] = []
    ) {
        self.mode = mode
        self.mailClients = mailClients
        self.protectedClassifications = protectedClassifications
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.mode = try container.decodeIfPresent(PolicyMode.self, forKey: .mode) ?? .disabled
        self.mailClients = try container.decodeIfPresent(
            [ApplicationRule].self,
            forKey: .mailClients
        ) ?? Self.defaultMailClients
        self.protectedClassifications = try container.decodeIfPresent(
            [String].self,
            forKey: .protectedClassifications
        ) ?? []
    }

    public func validate() throws {
        guard !mailClients.isEmpty, mailClients.count <= 32 else {
            throw PolicyValidationError.invalidCriterion(
                "emailAttachmentControl.mailClients must contain between 1 and 32 securely identified clients"
            )
        }
        var seenRuleIds = Set<String>()
        for rule in mailClients {
            try rule.validate(isAllowRule: true)
            guard seenRuleIds.insert(rule.ruleId).inserted else {
                throw PolicyValidationError.duplicateRuleId(
                    "Duplicate email mail-client ruleId '\(rule.ruleId)'"
                )
            }
        }

        guard protectedClassifications.count <= 100 else {
            throw PolicyValidationError.invalidCriterion(
                "emailAttachmentControl.protectedClassifications cannot contain more than 100 values"
            )
        }
        var seenClassifications = Set<String>()
        for classification in protectedClassifications {
            let trimmed = classification.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, trimmed.count <= 256 else {
                throw PolicyValidationError.invalidCriterion(
                    "emailAttachmentControl contains an invalid protected classification"
                )
            }
            guard seenClassifications.insert(trimmed.lowercased()).inserted else {
                throw PolicyValidationError.invalidCriterion(
                    "Duplicate protected email classification '\(trimmed)'"
                )
            }
        }
    }
}

public struct USBStorageControlConfig: Codable, Sendable, Equatable {
    public let mode: PolicyMode
    public let blockExternalStorage: Bool
    public let encryptionMode: PolicyMode
    public let containerSizePercent: Int

    public init(
        mode: PolicyMode = .enforce,
        blockExternalStorage: Bool = true,
        encryptionMode: PolicyMode = .disabled,
        containerSizePercent: Int = 90
    ) {
        self.mode = mode
        self.blockExternalStorage = blockExternalStorage
        self.encryptionMode = encryptionMode
        self.containerSizePercent = containerSizePercent
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.mode = try container.decode(PolicyMode.self, forKey: .mode)
        self.blockExternalStorage = try container.decodeIfPresent(
            Bool.self,
            forKey: .blockExternalStorage
        ) ?? true
        self.encryptionMode = try container.decodeIfPresent(
            PolicyMode.self,
            forKey: .encryptionMode
        ) ?? .disabled
        self.containerSizePercent = try container.decodeIfPresent(
            Int.self,
            forKey: .containerSizePercent
        ) ?? 90
    }

    public func validate() throws {
        guard (10...95).contains(containerSizePercent) else {
            throw PolicyValidationError.invalidCriterion(
                "usbStorageControl.containerSizePercent must be between 10 and 95"
            )
        }

        guard encryptionMode == .disabled || mode != .enforce || !blockExternalStorage else {
            throw PolicyValidationError.invalidCriterion(
                "USB mount blocking and encrypted-container enforcement cannot both be enabled"
            )
        }
    }
}

/// Controls outbound file reads performed by macOS nearby-sharing services.
/// Incoming transfers use write access and are deliberately left untouched.
public struct NearbyTransferControlConfig: Codable, Sendable, Equatable {
    public let mode: PolicyMode
    public let blockAirDrop: Bool
    public let blockBluetoothFileTransfer: Bool
    public let protectedDirectoryNames: [String]

    public init(
        mode: PolicyMode = .disabled,
        blockAirDrop: Bool = true,
        blockBluetoothFileTransfer: Bool = true,
        protectedDirectoryNames: [String] = WebUploadControlConfig.defaultProtectedDirectoryNames
    ) {
        self.mode = mode
        self.blockAirDrop = blockAirDrop
        self.blockBluetoothFileTransfer = blockBluetoothFileTransfer
        self.protectedDirectoryNames = protectedDirectoryNames
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.mode = try container.decode(PolicyMode.self, forKey: .mode)
        self.blockAirDrop = try container.decodeIfPresent(Bool.self, forKey: .blockAirDrop) ?? true
        self.blockBluetoothFileTransfer = try container.decodeIfPresent(
            Bool.self,
            forKey: .blockBluetoothFileTransfer
        ) ?? true
        self.protectedDirectoryNames = try container.decodeIfPresent(
            [String].self,
            forKey: .protectedDirectoryNames
        ) ?? WebUploadControlConfig.defaultProtectedDirectoryNames
    }

    public func validate() throws {
        guard !protectedDirectoryNames.isEmpty else {
            throw PolicyValidationError.invalidCriterion(
                "nearbyTransferControl.protectedDirectoryNames cannot be empty"
            )
        }

        var seen = Set<String>()
        for directoryName in protectedDirectoryNames {
            let trimmed = directoryName.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty,
                  trimmed != ".",
                  trimmed != "..",
                  !trimmed.contains("/") else {
                throw PolicyValidationError.invalidCriterion(
                    "Nearby-transfer protected directory names must be single safe path components"
                )
            }
            guard seen.insert(trimmed.lowercased()).inserted else {
                throw PolicyValidationError.invalidCriterion(
                    "Duplicate nearby-transfer protected directory name '\(trimmed)'"
                )
            }
        }
    }
}

/// User-session clipboard policy enforced by the Velox host agent.
///
/// macOS does not expose clipboard authorization events through Endpoint Security,
/// so the host observes NSPasteboard changes and removes newly copied data when
/// this policy requires it. Rules use the same signed-process identity model as
/// application control instead of trusting a display name.
public enum ClipboardControlMode: String, Codable, Sendable, Equatable {
    case disabled
    case blockAll = "block-all"
    case blockSelectedApplications = "block-selected-apps"
}

public struct ClipboardControlConfig: Codable, Sendable, Equatable {
    public let mode: ClipboardControlMode
    public let blockedApplications: [ApplicationRule]

    public init(
        mode: ClipboardControlMode = .disabled,
        blockedApplications: [ApplicationRule] = []
    ) {
        self.mode = mode
        self.blockedApplications = blockedApplications
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.mode = try container.decode(ClipboardControlMode.self, forKey: .mode)
        self.blockedApplications = try container.decodeIfPresent(
            [ApplicationRule].self,
            forKey: .blockedApplications
        ) ?? []
    }

    public func validate() throws {
        var seenRuleIds = Set<String>()
        for rule in blockedApplications {
            try rule.validate(isAllowRule: false)
            guard seenRuleIds.insert(rule.ruleId).inserted else {
                throw PolicyValidationError.duplicateRuleId(
                    "Duplicate clipboard ruleId '\(rule.ruleId)' detected"
                )
            }
        }
    }
}

/// Controls physical printer queues managed by the local CUPS scheduler.
///
/// The first implementation blocks all configured printer queues. Content-aware
/// classification and watermarking require a separately installed CUPS filter and
/// are intentionally not represented as completed capabilities here.
public struct PrinterControlConfig: Codable, Sendable, Equatable {
    public let mode: PolicyMode
    public let blockAllPrinters: Bool

    public init(
        mode: PolicyMode = .disabled,
        blockAllPrinters: Bool = true
    ) {
        self.mode = mode
        self.blockAllPrinters = blockAllPrinters
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.mode = try container.decode(PolicyMode.self, forKey: .mode)
        self.blockAllPrinters = try container.decodeIfPresent(
            Bool.self,
            forKey: .blockAllPrinters
        ) ?? true
    }

    public func validate() throws {
        // Enforced by Codable enum and Boolean decoding.
    }
}

/// Classifies text extracted from images and scanned PDF pages.
///
/// Rules return privacy-safe identifiers and classification names. Matched OCR
/// text must remain in memory and must never be written to the activity log.
public enum OCRRuleType: String, Codable, Sendable, Equatable {
    case keyword
    case regularExpression = "regular-expression"
    case creditCard = "credit-card"
    case indianPAN = "indian-pan"
    case aadhaar
}

public enum OCRScreenshotRemediation: String, Codable, Sendable, Equatable {
    case quarantine
    case delete
}

public struct OCRClassificationRule: Codable, Sendable, Equatable {
    public let ruleId: String
    public let name: String
    public let classification: String
    public let type: OCRRuleType
    public let pattern: String?
    public let keywords: [String]
    public let minimumMatches: Int

    public init(
        ruleId: String,
        name: String,
        classification: String,
        type: OCRRuleType,
        pattern: String? = nil,
        keywords: [String] = [],
        minimumMatches: Int = 1
    ) {
        self.ruleId = ruleId
        self.name = name
        self.classification = classification
        self.type = type
        self.pattern = pattern
        self.keywords = keywords
        self.minimumMatches = minimumMatches
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.ruleId = try container.decode(String.self, forKey: .ruleId)
        self.name = try container.decode(String.self, forKey: .name)
        self.classification = try container.decode(String.self, forKey: .classification)
        self.type = try container.decode(OCRRuleType.self, forKey: .type)
        self.pattern = try container.decodeIfPresent(String.self, forKey: .pattern)
        self.keywords = try container.decodeIfPresent([String].self, forKey: .keywords) ?? []
        self.minimumMatches = try container.decodeIfPresent(Int.self, forKey: .minimumMatches) ?? 1
    }

    public func validate() throws {
        let trimmedRuleId = ruleId.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedClassification = classification.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedRuleId.isEmpty, trimmedRuleId.count <= 256 else {
            throw PolicyValidationError.emptyRuleId("OCR rule ID cannot be empty")
        }
        guard !trimmedName.isEmpty, trimmedName.count <= 256,
              !trimmedClassification.isEmpty, trimmedClassification.count <= 256 else {
            throw PolicyValidationError.emptyCriterion(
                "OCR rule '\(ruleId)' requires a name and classification of at most 256 characters"
            )
        }
        guard (1...100).contains(minimumMatches) else {
            throw PolicyValidationError.invalidCriterion(
                "OCR rule '\(ruleId)' minimumMatches must be between 1 and 100"
            )
        }

        switch type {
        case .keyword:
            guard !keywords.isEmpty, keywords.count <= 64 else {
                throw PolicyValidationError.invalidCriterion(
                    "OCR keyword rule '\(ruleId)' must contain between 1 and 64 keywords"
                )
            }
            var seen = Set<String>()
            for keyword in keywords {
                let normalized = keyword.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                guard !normalized.isEmpty, normalized.count <= 128 else {
                    throw PolicyValidationError.invalidCriterion(
                        "OCR keyword rule '\(ruleId)' contains an empty or oversized keyword"
                    )
                }
                guard seen.insert(normalized).inserted else {
                    throw PolicyValidationError.duplicateRuleId(
                        "OCR keyword rule '\(ruleId)' contains duplicate keyword '\(normalized)'"
                    )
                }
            }
            guard pattern == nil else {
                throw PolicyValidationError.invalidCriterion(
                    "OCR keyword rule '\(ruleId)' cannot also define a regex pattern"
                )
            }
        case .regularExpression:
            guard keywords.isEmpty,
                  let pattern,
                  !pattern.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  pattern.count <= 512 else {
                throw PolicyValidationError.invalidCriterion(
                    "OCR regex rule '\(ruleId)' requires one pattern of at most 512 characters"
                )
            }
            do {
                _ = try NSRegularExpression(pattern: pattern)
            } catch {
                throw PolicyValidationError.invalidCriterion(
                    "OCR regex rule '\(ruleId)' has an invalid pattern"
                )
            }
        case .creditCard, .indianPAN, .aadhaar:
            guard pattern == nil, keywords.isEmpty else {
                throw PolicyValidationError.invalidCriterion(
                    "Built-in OCR rule '\(ruleId)' cannot define pattern or keywords"
                )
            }
        }
    }
}

public enum ClassifiedEgressChannel: String, Codable, CaseIterable, Sendable {
    case usb
    case webUpload = "web-upload"
    case email
    case nearbyTransfer = "nearby-transfer"
}

public struct OCRControlConfig: Codable, Sendable, Equatable {
    public static let defaultRules: [OCRClassificationRule] = [
        OCRClassificationRule(
            ruleId: "ocr-payment-card",
            name: "Payment card number",
            classification: "Payment Card Data",
            type: .creditCard
        ),
        OCRClassificationRule(
            ruleId: "ocr-indian-pan",
            name: "Indian PAN",
            classification: "Indian Tax Identifier",
            type: .indianPAN
        ),
        OCRClassificationRule(
            ruleId: "ocr-aadhaar",
            name: "Aadhaar number",
            classification: "Indian Identity Data",
            type: .aadhaar
        ),
        OCRClassificationRule(
            ruleId: "ocr-confidential-keywords",
            name: "Confidential document markers",
            classification: "Confidential Document",
            type: .keyword,
            keywords: ["confidential", "restricted", "internal only"]
        )
    ]

    public let mode: PolicyMode
    /// Applies the active OCR classifications to outbound file-transfer paths.
    /// Unknown files are denied in enforce mode and classified asynchronously.
    public let egressMode: PolicyMode
    public let protectedEgressChannels: [ClassifiedEgressChannel]
    /// Empty means every classification produced by an active OCR rule.
    public let protectedEgressClassifications: [String]
    public let screenshotMode: PolicyMode
    public let screenshotRemediation: OCRScreenshotRemediation
    public let recognitionLanguages: [String]
    public let minimumConfidence: Double
    public let maxFileSizeMB: Int
    public let maxPDFPages: Int
    public let rules: [OCRClassificationRule]

    public init(
        mode: PolicyMode = .disabled,
        egressMode: PolicyMode = .disabled,
        protectedEgressChannels: [ClassifiedEgressChannel] = ClassifiedEgressChannel.allCases,
        protectedEgressClassifications: [String] = [],
        screenshotMode: PolicyMode = .disabled,
        screenshotRemediation: OCRScreenshotRemediation = .quarantine,
        recognitionLanguages: [String] = ["en-US"],
        minimumConfidence: Double = 0.50,
        maxFileSizeMB: Int = 100,
        maxPDFPages: Int = 100,
        rules: [OCRClassificationRule] = OCRControlConfig.defaultRules
    ) {
        self.mode = mode
        self.egressMode = egressMode
        self.protectedEgressChannels = protectedEgressChannels
        self.protectedEgressClassifications = protectedEgressClassifications
        self.screenshotMode = screenshotMode
        self.screenshotRemediation = screenshotRemediation
        self.recognitionLanguages = recognitionLanguages
        self.minimumConfidence = minimumConfidence
        self.maxFileSizeMB = maxFileSizeMB
        self.maxPDFPages = maxPDFPages
        self.rules = rules
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.mode = try container.decodeIfPresent(PolicyMode.self, forKey: .mode) ?? .disabled
        self.egressMode = try container.decodeIfPresent(
            PolicyMode.self,
            forKey: .egressMode
        ) ?? .disabled
        self.protectedEgressChannels = try container.decodeIfPresent(
            [ClassifiedEgressChannel].self,
            forKey: .protectedEgressChannels
        ) ?? ClassifiedEgressChannel.allCases
        self.protectedEgressClassifications = try container.decodeIfPresent(
            [String].self,
            forKey: .protectedEgressClassifications
        ) ?? []
        self.screenshotMode = try container.decodeIfPresent(
            PolicyMode.self,
            forKey: .screenshotMode
        ) ?? .disabled
        self.screenshotRemediation = try container.decodeIfPresent(
            OCRScreenshotRemediation.self,
            forKey: .screenshotRemediation
        ) ?? .quarantine
        self.recognitionLanguages = try container.decodeIfPresent(
            [String].self,
            forKey: .recognitionLanguages
        ) ?? ["en-US"]
        self.minimumConfidence = try container.decodeIfPresent(
            Double.self,
            forKey: .minimumConfidence
        ) ?? 0.50
        self.maxFileSizeMB = try container.decodeIfPresent(
            Int.self,
            forKey: .maxFileSizeMB
        ) ?? 100
        self.maxPDFPages = try container.decodeIfPresent(
            Int.self,
            forKey: .maxPDFPages
        ) ?? 100
        self.rules = try container.decodeIfPresent(
            [OCRClassificationRule].self,
            forKey: .rules
        ) ?? Self.defaultRules
    }

    public func validate() throws {
        guard !protectedEgressChannels.isEmpty,
              protectedEgressChannels.count <= ClassifiedEgressChannel.allCases.count,
              Set(protectedEgressChannels.map(\.rawValue)).count == protectedEgressChannels.count else {
            throw PolicyValidationError.invalidCriterion(
                "ocrControl.protectedEgressChannels must contain unique supported channels"
            )
        }
        guard protectedEgressClassifications.count <= 100 else {
            throw PolicyValidationError.invalidCriterion(
                "ocrControl.protectedEgressClassifications cannot contain more than 100 values"
            )
        }
        var seenEgressClassifications = Set<String>()
        for classification in protectedEgressClassifications {
            let trimmed = classification.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, trimmed.count <= 256,
                  seenEgressClassifications.insert(trimmed.lowercased()).inserted else {
                throw PolicyValidationError.invalidCriterion(
                    "ocrControl contains an invalid or duplicate protected egress classification"
                )
            }
        }
        guard (0...1).contains(minimumConfidence) else {
            throw PolicyValidationError.invalidCriterion(
                "ocrControl.minimumConfidence must be between 0 and 1"
            )
        }
        guard (1...500).contains(maxFileSizeMB) else {
            throw PolicyValidationError.invalidCriterion(
                "ocrControl.maxFileSizeMB must be between 1 and 500"
            )
        }
        guard (1...500).contains(maxPDFPages) else {
            throw PolicyValidationError.invalidCriterion(
                "ocrControl.maxPDFPages must be between 1 and 500"
            )
        }
        guard !recognitionLanguages.isEmpty, recognitionLanguages.count <= 8 else {
            throw PolicyValidationError.invalidCriterion(
                "ocrControl.recognitionLanguages must contain between 1 and 8 language identifiers"
            )
        }
        var seenLanguages = Set<String>()
        for language in recognitionLanguages {
            let trimmed = language.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty,
                  trimmed.count <= 35,
                  trimmed.unicodeScalars.allSatisfy({
                      CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_"
                  }) else {
                throw PolicyValidationError.invalidCriterion(
                    "ocrControl contains an invalid recognition language identifier"
                )
            }
            guard seenLanguages.insert(trimmed.lowercased()).inserted else {
                throw PolicyValidationError.invalidCriterion(
                    "ocrControl contains duplicate recognition language '\(trimmed)'"
                )
            }
        }

        guard rules.count <= 100 else {
            throw PolicyValidationError.invalidCriterion(
                "ocrControl.rules cannot contain more than 100 rules"
            )
        }
        var seenRuleIds = Set<String>()
        for rule in rules {
            try rule.validate()
            guard seenRuleIds.insert(rule.ruleId).inserted else {
                throw PolicyValidationError.duplicateRuleId(
                    "Duplicate OCR ruleId '\(rule.ruleId)' detected"
                )
            }
        }
    }
}

/// Scheduled at-rest discovery for user data, mounted local volumes, and
/// mounted network shares. The host agent performs scans asynchronously so
/// filesystem traversal and content extraction never consume an Endpoint
/// Security authorization deadline.
public struct EndpointDiscoveryControlConfig: Codable, Sendable, Equatable {
    public let mode: PolicyMode
    public let scheduleIntervalMinutes: Int
    public let includeLocalHome: Bool
    public let includeMountedVolumes: Bool
    public let includeMountedShares: Bool
    public let tagClassifiedFiles: Bool
    public let maxFilesPerScan: Int

    public init(
        mode: PolicyMode = .disabled,
        scheduleIntervalMinutes: Int = 1_440,
        includeLocalHome: Bool = true,
        includeMountedVolumes: Bool = true,
        includeMountedShares: Bool = true,
        tagClassifiedFiles: Bool = true,
        maxFilesPerScan: Int = 10_000
    ) {
        self.mode = mode
        self.scheduleIntervalMinutes = scheduleIntervalMinutes
        self.includeLocalHome = includeLocalHome
        self.includeMountedVolumes = includeMountedVolumes
        self.includeMountedShares = includeMountedShares
        self.tagClassifiedFiles = tagClassifiedFiles
        self.maxFilesPerScan = maxFilesPerScan
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.mode = try container.decodeIfPresent(PolicyMode.self, forKey: .mode) ?? .disabled
        self.scheduleIntervalMinutes = try container.decodeIfPresent(
            Int.self,
            forKey: .scheduleIntervalMinutes
        ) ?? 1_440
        self.includeLocalHome = try container.decodeIfPresent(
            Bool.self,
            forKey: .includeLocalHome
        ) ?? true
        self.includeMountedVolumes = try container.decodeIfPresent(
            Bool.self,
            forKey: .includeMountedVolumes
        ) ?? true
        self.includeMountedShares = try container.decodeIfPresent(
            Bool.self,
            forKey: .includeMountedShares
        ) ?? true
        self.tagClassifiedFiles = try container.decodeIfPresent(
            Bool.self,
            forKey: .tagClassifiedFiles
        ) ?? true
        self.maxFilesPerScan = try container.decodeIfPresent(
            Int.self,
            forKey: .maxFilesPerScan
        ) ?? 10_000
    }

    public func validate() throws {
        guard (15...10_080).contains(scheduleIntervalMinutes) else {
            throw PolicyValidationError.invalidCriterion(
                "endpointDiscoveryControl.scheduleIntervalMinutes must be between 15 and 10080"
            )
        }
        guard (100...100_000).contains(maxFilesPerScan) else {
            throw PolicyValidationError.invalidCriterion(
                "endpointDiscoveryControl.maxFilesPerScan must be between 100 and 100000"
            )
        }
        guard includeLocalHome || includeMountedVolumes || includeMountedShares else {
            throw PolicyValidationError.invalidCriterion(
                "endpointDiscoveryControl must include at least one scan location"
            )
        }
    }
}

// These policy shapes complete the already-wired console mutation methods. The
// enforcement implementations remain separate features and must not be reported
// as active merely because their policy can be stored.
public struct CloudSyncControlConfig: Codable, Sendable, Equatable {
    public let mode: PolicyMode
    public let blockCloudSync: Bool
    public let monitoredProviders: [String]

    public init(
        mode: PolicyMode = .disabled,
        blockCloudSync: Bool = true,
        monitoredProviders: [String] = ["iCloud", "OneDrive", "Google Drive", "Dropbox", "Box"]
    ) {
        self.mode = mode
        self.blockCloudSync = blockCloudSync
        self.monitoredProviders = monitoredProviders
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.mode = try container.decodeIfPresent(PolicyMode.self, forKey: .mode) ?? .disabled
        self.blockCloudSync = try container.decodeIfPresent(Bool.self, forKey: .blockCloudSync) ?? true
        self.monitoredProviders = try container.decodeIfPresent(
            [String].self,
            forKey: .monitoredProviders
        ) ?? ["iCloud", "OneDrive", "Google Drive", "Dropbox", "Box"]
    }
}

public struct OpticalDiskImageControlConfig: Codable, Sendable, Equatable {
    public let mode: PolicyMode
    public let blockDiskImages: Bool
    public let blockOpticalMedia: Bool

    public init(
        mode: PolicyMode = .disabled,
        blockDiskImages: Bool = true,
        blockOpticalMedia: Bool = true
    ) {
        self.mode = mode
        self.blockDiskImages = blockDiskImages
        self.blockOpticalMedia = blockOpticalMedia
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.mode = try container.decodeIfPresent(PolicyMode.self, forKey: .mode) ?? .disabled
        self.blockDiskImages = try container.decodeIfPresent(Bool.self, forKey: .blockDiskImages) ?? true
        self.blockOpticalMedia = try container.decodeIfPresent(Bool.self, forKey: .blockOpticalMedia) ?? true
    }

    public func validate() throws {
        guard mode == .disabled || blockDiskImages || blockOpticalMedia else {
            throw PolicyValidationError.invalidCriterion(
                "opticalDiskImageControl must select disk images, optical media, or both when active"
            )
        }
    }
}

public struct ScreenWatermarkingConfig: Codable, Sendable, Equatable {
    public let mode: PolicyMode
    public let text: String
    public let opacity: Double

    public init(
        mode: PolicyMode = .disabled,
        text: String = "Protected by Velox DLP",
        opacity: Double = 0.18
    ) {
        self.mode = mode
        self.text = text
        self.opacity = opacity
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.mode = try container.decodeIfPresent(PolicyMode.self, forKey: .mode) ?? .disabled
        self.text = try container.decodeIfPresent(String.self, forKey: .text) ?? "Protected by Velox DLP"
        self.opacity = try container.decodeIfPresent(Double.self, forKey: .opacity) ?? 0.18
    }
}

public struct PrintToPDFControlConfig: Codable, Sendable, Equatable {
    public let mode: PolicyMode
    public let blockSaveAsPDF: Bool

    public init(mode: PolicyMode = .disabled, blockSaveAsPDF: Bool = true) {
        self.mode = mode
        self.blockSaveAsPDF = blockSaveAsPDF
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.mode = try container.decodeIfPresent(PolicyMode.self, forKey: .mode) ?? .disabled
        self.blockSaveAsPDF = try container.decodeIfPresent(Bool.self, forKey: .blockSaveAsPDF) ?? true
    }
}

public enum NetworkProtocol: String, Codable, Sendable, Equatable {
    case any
    case tcp
    case udp
}

public enum NetworkDefaultAction: String, Codable, Sendable, Equatable {
    case allow
    case block
}

public struct NetworkDestinationRule: Codable, Sendable, Equatable {
    public let ruleId: String
    public let domain: String?
    public let ipAddress: String?
    public let cidrRange: String?
    public let port: Int?
    public let portRange: String?
    public let `protocol`: NetworkProtocol
    public let process: ApplicationRule?
    public let action: String

    public init(
        ruleId: String,
        domain: String? = nil,
        ipAddress: String? = nil,
        cidrRange: String? = nil,
        port: Int? = nil,
        portRange: String? = nil,
        `protocol`: NetworkProtocol = .any,
        process: ApplicationRule? = nil,
        action: String = "block"
    ) {
        self.ruleId = ruleId
        self.domain = domain
        self.ipAddress = ipAddress
        self.cidrRange = cidrRange
        self.port = port
        self.portRange = portRange
        self.`protocol` = `protocol`
        self.process = process
        self.action = action.lowercased()
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.ruleId = try container.decode(String.self, forKey: .ruleId)
        self.domain = try container.decodeIfPresent(String.self, forKey: .domain)
        self.ipAddress = try container.decodeIfPresent(String.self, forKey: .ipAddress)
        self.cidrRange = try container.decodeIfPresent(String.self, forKey: .cidrRange)
        self.port = try container.decodeIfPresent(Int.self, forKey: .port)
        self.portRange = try container.decodeIfPresent(String.self, forKey: .portRange)
        self.`protocol` = try container.decodeIfPresent(NetworkProtocol.self, forKey: .`protocol`) ?? .any
        self.process = try container.decodeIfPresent(ApplicationRule.self, forKey: .process)
        self.action = (try container.decodeIfPresent(String.self, forKey: .action) ?? "block").lowercased()
    }

    public func validate() throws {
        let trimmedRuleId = ruleId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedRuleId.isEmpty else {
            throw PolicyValidationError.emptyRuleId("Rule ID cannot be empty")
        }

        guard action == "allow" || action == "block" else {
            throw PolicyValidationError.invalidCriterion(
                "action in rule '\(ruleId)' must be either 'allow' or 'block', got '\(action)'"
            )
        }

        if let d = domain {
            let trimmed = d.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                throw PolicyValidationError.emptyCriterion("domain in rule '\(ruleId)' cannot be empty")
            }
            guard !trimmed.contains(" ") else {
                throw PolicyValidationError.invalidCriterion("domain in rule '\(ruleId)' cannot contain whitespace")
            }
        }

        if let ip = ipAddress {
            let trimmed = ip.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                throw PolicyValidationError.emptyCriterion("ipAddress in rule '\(ruleId)' cannot be empty")
            }
            var sin = sockaddr_in()
            var sin6 = sockaddr_in6()
            let isV4 = inet_pton(AF_INET, trimmed, &sin.sin_addr) == 1
            let isV6 = inet_pton(AF_INET6, trimmed, &sin6.sin6_addr) == 1
            guard isV4 || isV6 else {
                throw PolicyValidationError.invalidCriterion("ipAddress '\(trimmed)' in rule '\(ruleId)' is not a valid IPv4 or IPv6 address")
            }
        }

        if let cidr = cidrRange {
            let trimmed = cidr.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                throw PolicyValidationError.emptyCriterion("cidrRange in rule '\(ruleId)' cannot be empty")
            }
            let parts = trimmed.split(separator: "/", omittingEmptySubsequences: false)
            guard parts.count == 2,
                  let prefix = Int(parts[1]),
                  !parts[0].isEmpty else {
                throw PolicyValidationError.invalidCriterion("cidrRange '\(trimmed)' in rule '\(ruleId)' must be in format IP/prefix (e.g. 10.0.0.0/8)")
            }
            let ipPart = String(parts[0])
            var sin = sockaddr_in()
            var sin6 = sockaddr_in6()
            let isV4 = inet_pton(AF_INET, ipPart, &sin.sin_addr) == 1
            let isV6 = inet_pton(AF_INET6, ipPart, &sin6.sin6_addr) == 1
            guard (isV4 && (0...32).contains(prefix)) || (isV6 && (0...128).contains(prefix)) else {
                throw PolicyValidationError.invalidCriterion("cidrRange '\(trimmed)' in rule '\(ruleId)' has invalid IP or prefix range")
            }
        }

        if let p = port {
            guard (1...65535).contains(p) else {
                throw PolicyValidationError.invalidCriterion("port in rule '\(ruleId)' must be between 1 and 65535, got \(p)")
            }
        }

        if let pr = portRange {
            let trimmed = pr.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                throw PolicyValidationError.emptyCriterion("portRange in rule '\(ruleId)' cannot be empty")
            }
            let parts = trimmed.split(separator: "-", omittingEmptySubsequences: false)
            guard parts.count == 2,
                  let start = Int(parts[0]),
                  let end = Int(parts[1]),
                  (1...65535).contains(start),
                  (1...65535).contains(end),
                  start <= end else {
                throw PolicyValidationError.invalidCriterion("portRange '\(trimmed)' in rule '\(ruleId)' must be formatted as 'start-end' with 1 <= start <= end <= 65535")
            }
        }

        let hasDestinationCriterion = domain != nil || ipAddress != nil || cidrRange != nil || port != nil || portRange != nil
        let hasCriterion = hasDestinationCriterion || process != nil
        guard hasCriterion else {
            throw PolicyValidationError.missingCriterion("Network rule '\(ruleId)' must specify at least one destination criterion or process selector")
        }

        if let proc = process {
            try proc.validate(isAllowRule: action == "allow")
        }
    }
}

public struct NetworkFlowControlConfig: Codable, Sendable, Equatable {
    public let mode: PolicyMode
    public let defaultAction: NetworkDefaultAction
    public let rules: [NetworkDestinationRule]

    public init(
        mode: PolicyMode = .disabled,
        defaultAction: NetworkDefaultAction = .allow,
        rules: [NetworkDestinationRule] = []
    ) {
        self.mode = mode
        self.defaultAction = defaultAction
        self.rules = rules
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.mode = try container.decode(PolicyMode.self, forKey: .mode)
        self.defaultAction = try container.decodeIfPresent(NetworkDefaultAction.self, forKey: .defaultAction) ?? .allow
        self.rules = try container.decodeIfPresent([NetworkDestinationRule].self, forKey: .rules) ?? []
    }

    public func validate() throws {
        var seenRuleIds = Set<String>()
        for rule in rules {
            try rule.validate()
            guard seenRuleIds.insert(rule.ruleId).inserted else {
                throw PolicyValidationError.duplicateRuleId(
                    "Duplicate networkFlowControl ruleId '\(rule.ruleId)' detected"
                )
            }
        }
    }
}

public struct VeloxPolicy: Codable, Sendable, Equatable {
    public let policyVersion: Int
    public let applicationControl: ApplicationControlConfig
    public let webUploadControl: WebUploadControlConfig
    public let emailAttachmentControl: EmailAttachmentControlConfig
    public let usbStorageControl: USBStorageControlConfig
    public let nearbyTransferControl: NearbyTransferControlConfig
    public let clipboardControl: ClipboardControlConfig
    public let printerControl: PrinterControlConfig
    public let ocrControl: OCRControlConfig
    public let endpointDiscoveryControl: EndpointDiscoveryControlConfig
    public let networkFlowControl: NetworkFlowControlConfig
    public let cloudSyncControl: CloudSyncControlConfig
    public let opticalDiskImageControl: OpticalDiskImageControlConfig
    public let screenWatermarking: ScreenWatermarkingConfig
    public let printToPDFControl: PrintToPDFControlConfig

    public init(
        policyVersion: Int,
        applicationControl: ApplicationControlConfig,
        webUploadControl: WebUploadControlConfig = WebUploadControlConfig(),
        emailAttachmentControl: EmailAttachmentControlConfig = EmailAttachmentControlConfig(),
        usbStorageControl: USBStorageControlConfig = USBStorageControlConfig(),
        nearbyTransferControl: NearbyTransferControlConfig = NearbyTransferControlConfig(),
        clipboardControl: ClipboardControlConfig = ClipboardControlConfig(),
        printerControl: PrinterControlConfig = PrinterControlConfig(),
        ocrControl: OCRControlConfig = OCRControlConfig(),
        endpointDiscoveryControl: EndpointDiscoveryControlConfig = EndpointDiscoveryControlConfig(),
        networkFlowControl: NetworkFlowControlConfig = NetworkFlowControlConfig(),
        cloudSyncControl: CloudSyncControlConfig = CloudSyncControlConfig(),
        opticalDiskImageControl: OpticalDiskImageControlConfig = OpticalDiskImageControlConfig(),
        screenWatermarking: ScreenWatermarkingConfig = ScreenWatermarkingConfig(),
        printToPDFControl: PrintToPDFControlConfig = PrintToPDFControlConfig()
    ) {
        self.policyVersion = policyVersion
        self.applicationControl = applicationControl
        self.webUploadControl = webUploadControl
        self.emailAttachmentControl = emailAttachmentControl
        self.usbStorageControl = usbStorageControl
        self.nearbyTransferControl = nearbyTransferControl
        self.clipboardControl = clipboardControl
        self.printerControl = printerControl
        self.ocrControl = ocrControl
        self.endpointDiscoveryControl = endpointDiscoveryControl
        self.networkFlowControl = networkFlowControl
        self.cloudSyncControl = cloudSyncControl
        self.opticalDiskImageControl = opticalDiskImageControl
        self.screenWatermarking = screenWatermarking
        self.printToPDFControl = printToPDFControl
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.policyVersion = try container.decode(Int.self, forKey: .policyVersion)
        self.applicationControl = try container.decode(ApplicationControlConfig.self, forKey: .applicationControl)
        self.webUploadControl = try container.decodeIfPresent(
            WebUploadControlConfig.self,
            forKey: .webUploadControl
        ) ?? WebUploadControlConfig()
        self.emailAttachmentControl = try container.decodeIfPresent(
            EmailAttachmentControlConfig.self,
            forKey: .emailAttachmentControl
        ) ?? EmailAttachmentControlConfig()
        self.usbStorageControl = try container.decodeIfPresent(
            USBStorageControlConfig.self,
            forKey: .usbStorageControl
        ) ?? USBStorageControlConfig()
        self.nearbyTransferControl = try container.decodeIfPresent(
            NearbyTransferControlConfig.self,
            forKey: .nearbyTransferControl
        ) ?? NearbyTransferControlConfig()
        self.clipboardControl = try container.decodeIfPresent(
            ClipboardControlConfig.self,
            forKey: .clipboardControl
        ) ?? ClipboardControlConfig()
        self.printerControl = try container.decodeIfPresent(
            PrinterControlConfig.self,
            forKey: .printerControl
        ) ?? PrinterControlConfig()
        self.ocrControl = try container.decodeIfPresent(
            OCRControlConfig.self,
            forKey: .ocrControl
        ) ?? OCRControlConfig()
        self.endpointDiscoveryControl = try container.decodeIfPresent(
            EndpointDiscoveryControlConfig.self,
            forKey: .endpointDiscoveryControl
        ) ?? EndpointDiscoveryControlConfig()
        self.networkFlowControl = try container.decodeIfPresent(
            NetworkFlowControlConfig.self,
            forKey: .networkFlowControl
        ) ?? NetworkFlowControlConfig()
        self.cloudSyncControl = try container.decodeIfPresent(
            CloudSyncControlConfig.self,
            forKey: .cloudSyncControl
        ) ?? CloudSyncControlConfig()
        self.opticalDiskImageControl = try container.decodeIfPresent(
            OpticalDiskImageControlConfig.self,
            forKey: .opticalDiskImageControl
        ) ?? OpticalDiskImageControlConfig()
        self.screenWatermarking = try container.decodeIfPresent(
            ScreenWatermarkingConfig.self,
            forKey: .screenWatermarking
        ) ?? ScreenWatermarkingConfig()
        self.printToPDFControl = try container.decodeIfPresent(
            PrintToPDFControlConfig.self,
            forKey: .printToPDFControl
        ) ?? PrintToPDFControlConfig()
    }

    /// Strictly parses and validates JSON data, rejecting any unknown properties or malformed fields.
    public static func decodeStrict(from data: Data) throws -> VeloxPolicy {
        guard let jsonObject = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PolicyValidationError.malformedJSON("Root JSON must be an object")
        }

        // Validate top-level keys
        let validTopKeys: Set<String> = [
            "policyVersion",
            "applicationControl",
            "webUploadControl",
            "emailAttachmentControl",
            "usbStorageControl",
            "nearbyTransferControl",
            "clipboardControl",
            "printerControl",
            "ocrControl",
            "endpointDiscoveryControl",
            "networkFlowControl",
            "cloudSyncControl",
            "opticalDiskImageControl",
            "screenWatermarking",
            "printToPDFControl"
        ]
        for key in jsonObject.keys {
            if !validTopKeys.contains(key) {
                throw PolicyValidationError.unknownProperty("Unknown property '\(key)' at policy root")
            }
        }

        guard let appControlObj = jsonObject["applicationControl"] as? [String: Any] else {
            throw PolicyValidationError.missingCriterion("applicationControl object is required")
        }

        // Validate applicationControl keys
        let validAppControlKeys: Set<String> = ["mode", "blockedApplications", "allowedApplications"]
        for key in appControlObj.keys {
            if !validAppControlKeys.contains(key) {
                throw PolicyValidationError.unknownProperty("Unknown property '\(key)' in applicationControl")
            }
        }

        // Validate rules for unknown keys
        let validRuleKeys: Set<String> = [
            "ruleId", "signingId", "teamId", "isPlatformBinary",
            "cdhash", "executablePath", "executablePathPrefix"
        ]

        if let blockedList = appControlObj["blockedApplications"] as? [[String: Any]] {
            for ruleDict in blockedList {
                for key in ruleDict.keys {
                    if !validRuleKeys.contains(key) {
                        throw PolicyValidationError.unknownProperty("Unknown property '\(key)' in blocked rule")
                    }
                }
            }
        }

        if let allowedList = appControlObj["allowedApplications"] as? [[String: Any]] {
            for ruleDict in allowedList {
                for key in ruleDict.keys {
                    if !validRuleKeys.contains(key) {
                        throw PolicyValidationError.unknownProperty("Unknown property '\(key)' in allowed rule")
                    }
                }
            }
        }

        if let webUploadObj = jsonObject["webUploadControl"] as? [String: Any] {
            let validWebUploadKeys: Set<String> = ["mode", "protectedDirectoryNames"]
            for key in webUploadObj.keys {
                if !validWebUploadKeys.contains(key) {
                    throw PolicyValidationError.unknownProperty(
                        "Unknown property '\(key)' in webUploadControl"
                    )
                }
            }
        }

        if let emailObj = jsonObject["emailAttachmentControl"] as? [String: Any] {
            let validEmailKeys: Set<String> = ["mode", "mailClients", "protectedClassifications"]
            for key in emailObj.keys where !validEmailKeys.contains(key) {
                throw PolicyValidationError.unknownProperty(
                    "Unknown property '\(key)' in emailAttachmentControl"
                )
            }
            if let mailClients = emailObj["mailClients"] as? [[String: Any]] {
                for ruleDict in mailClients {
                    for key in ruleDict.keys where !validRuleKeys.contains(key) {
                        throw PolicyValidationError.unknownProperty(
                            "Unknown property '\(key)' in emailAttachmentControl mail client"
                        )
                    }
                }
            }
        }

        if let usbStorageObj = jsonObject["usbStorageControl"] as? [String: Any] {
            let validUsbKeys: Set<String> = [
                "mode",
                "blockExternalStorage",
                "encryptionMode",
                "containerSizePercent"
            ]
            for key in usbStorageObj.keys {
                if !validUsbKeys.contains(key) {
                    throw PolicyValidationError.unknownProperty(
                        "Unknown property '\(key)' in usbStorageControl"
                    )
                }
            }
        }

        if let nearbyTransferObj = jsonObject["nearbyTransferControl"] as? [String: Any] {
            let validNearbyKeys: Set<String> = [
                "mode",
                "blockAirDrop",
                "blockBluetoothFileTransfer",
                "protectedDirectoryNames"
            ]
            for key in nearbyTransferObj.keys {
                if !validNearbyKeys.contains(key) {
                    throw PolicyValidationError.unknownProperty(
                        "Unknown property '\(key)' in nearbyTransferControl"
                    )
                }
            }
        }

        if let clipboardObj = jsonObject["clipboardControl"] as? [String: Any] {
            let validClipboardKeys: Set<String> = ["mode", "blockedApplications"]
            for key in clipboardObj.keys {
                if !validClipboardKeys.contains(key) {
                    throw PolicyValidationError.unknownProperty(
                        "Unknown property '\(key)' in clipboardControl"
                    )
                }
            }

            if let blockedList = clipboardObj["blockedApplications"] as? [[String: Any]] {
                for ruleDict in blockedList {
                    for key in ruleDict.keys {
                        if !validRuleKeys.contains(key) {
                            throw PolicyValidationError.unknownProperty(
                                "Unknown property '\(key)' in clipboard blocked rule"
                            )
                        }
                    }
                }
            }
        }

        if let printerObj = jsonObject["printerControl"] as? [String: Any] {
            let validPrinterKeys: Set<String> = ["mode", "blockAllPrinters"]
            for key in printerObj.keys {
                if !validPrinterKeys.contains(key) {
                    throw PolicyValidationError.unknownProperty(
                        "Unknown property '\(key)' in printerControl"
                    )
                }
            }
        }

        if let ocrObj = jsonObject["ocrControl"] as? [String: Any] {
            let validOCRKeys: Set<String> = [
                "mode", "egressMode", "protectedEgressChannels",
                "protectedEgressClassifications", "screenshotMode", "screenshotRemediation",
                "recognitionLanguages", "minimumConfidence", "maxFileSizeMB",
                "maxPDFPages", "rules"
            ]
            for key in ocrObj.keys where !validOCRKeys.contains(key) {
                throw PolicyValidationError.unknownProperty(
                    "Unknown property '\(key)' in ocrControl"
                )
            }
            if let rules = ocrObj["rules"] as? [[String: Any]] {
                let validOCRRuleKeys: Set<String> = [
                    "ruleId", "name", "classification", "type",
                    "pattern", "keywords", "minimumMatches"
                ]
                for rule in rules {
                    for key in rule.keys where !validOCRRuleKeys.contains(key) {
                        throw PolicyValidationError.unknownProperty(
                            "Unknown property '\(key)' in ocrControl rule"
                        )
                    }
                }
            }
        }

        if let discoveryObj = jsonObject["endpointDiscoveryControl"] as? [String: Any] {
            let validDiscoveryKeys: Set<String> = [
                "mode", "scheduleIntervalMinutes", "includeLocalHome",
                "includeMountedVolumes", "includeMountedShares",
                "tagClassifiedFiles", "maxFilesPerScan"
            ]
            for key in discoveryObj.keys where !validDiscoveryKeys.contains(key) {
                throw PolicyValidationError.unknownProperty(
                    "Unknown property '\(key)' in endpointDiscoveryControl"
                )
            }
        }

        let supplementalObjects: [(String, Set<String>)] = [
            ("cloudSyncControl", ["mode", "blockCloudSync", "monitoredProviders"]),
            ("opticalDiskImageControl", ["mode", "blockDiskImages", "blockOpticalMedia"]),
            ("screenWatermarking", ["mode", "text", "opacity"]),
            ("printToPDFControl", ["mode", "blockSaveAsPDF"])
        ]
        for (objectName, validKeys) in supplementalObjects {
            guard let object = jsonObject[objectName] as? [String: Any] else { continue }
            for key in object.keys where !validKeys.contains(key) {
                throw PolicyValidationError.unknownProperty(
                    "Unknown property '\(key)' in \(objectName)"
                )
            }
        }

        if let networkFlowObj = jsonObject["networkFlowControl"] as? [String: Any] {
            let validNetworkFlowKeys: Set<String> = ["mode", "defaultAction", "rules"]
            for key in networkFlowObj.keys {
                if !validNetworkFlowKeys.contains(key) {
                    throw PolicyValidationError.unknownProperty(
                        "Unknown property '\(key)' in networkFlowControl"
                    )
                }
            }

            if let rulesList = networkFlowObj["rules"] as? [[String: Any]] {
                let validNetworkRuleKeys: Set<String> = [
                    "ruleId", "domain", "ipAddress", "cidrRange",
                    "port", "portRange", "protocol", "process", "action"
                ]
                for ruleDict in rulesList {
                    for key in ruleDict.keys {
                        if !validNetworkRuleKeys.contains(key) {
                            throw PolicyValidationError.unknownProperty(
                                "Unknown property '\(key)' in networkFlowControl rule"
                            )
                        }
                    }

                    if let processDict = ruleDict["process"] as? [String: Any] {
                        for key in processDict.keys {
                            if !validRuleKeys.contains(key) {
                                throw PolicyValidationError.unknownProperty(
                                    "Unknown property '\(key)' in networkFlowControl rule process"
                                )
                            }
                        }
                    }
                }
            }
        }

        let policy = try JSONDecoder().decode(VeloxPolicy.self, from: data)
        try policy.validate()
        return policy
    }

    public func validate() throws {
        guard policyVersion >= 1 else {
            throw PolicyValidationError.invalidVersion("Policy version must be >= 1, got \(policyVersion)")
        }

        try webUploadControl.validate()
        try emailAttachmentControl.validate()
        try usbStorageControl.validate()
        try nearbyTransferControl.validate()
        try clipboardControl.validate()
        try printerControl.validate()
        try ocrControl.validate()
        try endpointDiscoveryControl.validate()
        try opticalDiskImageControl.validate()

        let activeClassifications = Set(ocrControl.rules.map { $0.classification.lowercased() })
        for classification in ocrControl.protectedEgressClassifications {
            guard activeClassifications.contains(classification.lowercased()) else {
                throw PolicyValidationError.invalidCriterion(
                    "Egress classification '\(classification)' has no active OCR rule"
                )
            }
        }
        for classification in emailAttachmentControl.protectedClassifications {
            guard activeClassifications.contains(classification.lowercased()) else {
                throw PolicyValidationError.invalidCriterion(
                    "Email classification '\(classification)' has no active OCR rule"
                )
            }
        }
        try networkFlowControl.validate()

        guard (0...1).contains(screenWatermarking.opacity) else {
            throw PolicyValidationError.invalidCriterion(
                "screenWatermarking.opacity must be between 0 and 1"
            )
        }
        guard !screenWatermarking.text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw PolicyValidationError.invalidCriterion(
                "screenWatermarking.text cannot be empty"
            )
        }

        var seenRuleIds = Set<String>()
        for rule in applicationControl.allowedApplications {
            try rule.validate(isAllowRule: true)
            if seenRuleIds.contains(rule.ruleId) {
                throw PolicyValidationError.duplicateRuleId("Duplicate ruleId '\(rule.ruleId)' detected")
            }
            seenRuleIds.insert(rule.ruleId)
        }

        for rule in applicationControl.blockedApplications {
            try rule.validate(isAllowRule: false)
            if seenRuleIds.contains(rule.ruleId) {
                throw PolicyValidationError.duplicateRuleId("Duplicate ruleId '\(rule.ruleId)' detected")
            }
            seenRuleIds.insert(rule.ruleId)
        }
    }
}

public enum PolicyValidationError: Error, CustomStringConvertible, Equatable {
    case malformedJSON(String)
    case invalidVersion(String)
    case versionRollback(String)
    case emptyRuleId(String)
    case duplicateRuleId(String)
    case missingCriterion(String)
    case emptyCriterion(String)
    case invalidCriterion(String)
    case unsafePathPrefix(String)
    case unknownProperty(String)
    case insecureAllowRule(String)

    public var description: String {
        switch self {
        case .malformedJSON(let msg): return "Malformed JSON: \(msg)"
        case .invalidVersion(let msg): return "Invalid Version: \(msg)"
        case .versionRollback(let msg): return "Version Rollback: \(msg)"
        case .emptyRuleId(let msg): return "Empty Rule ID: \(msg)"
        case .duplicateRuleId(let msg): return "Duplicate Rule ID: \(msg)"
        case .missingCriterion(let msg): return "Missing Criterion: \(msg)"
        case .emptyCriterion(let msg): return "Empty Criterion: \(msg)"
        case .invalidCriterion(let msg): return "Invalid Criterion: \(msg)"
        case .unsafePathPrefix(let msg): return "Unsafe Path Prefix: \(msg)"
        case .unknownProperty(let msg): return "Unknown Property: \(msg)"
        case .insecureAllowRule(let msg): return "Insecure Allow Rule: \(msg)"
        }
    }
}
