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

public struct VeloxPolicy: Codable, Sendable, Equatable {
    public let policyVersion: Int
    public let applicationControl: ApplicationControlConfig

    public init(policyVersion: Int, applicationControl: ApplicationControlConfig) {
        self.policyVersion = policyVersion
        self.applicationControl = applicationControl
    }

    /// Strictly parses and validates JSON data, rejecting any unknown properties or malformed fields.
    public static func decodeStrict(from data: Data) throws -> VeloxPolicy {
        guard let jsonObject = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PolicyValidationError.malformedJSON("Root JSON must be an object")
        }

        // Validate top-level keys
        let validTopKeys: Set<String> = ["policyVersion", "applicationControl"]
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

        let policy = try JSONDecoder().decode(VeloxPolicy.self, from: data)
        try policy.validate()
        return policy
    }

    public func validate() throws {
        guard policyVersion >= 1 else {
            throw PolicyValidationError.invalidVersion("Policy version must be >= 1, got \(policyVersion)")
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
