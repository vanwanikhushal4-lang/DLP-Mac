import Foundation

/// Content-only decision shared by every file egress surface. The record is
/// created asynchronously and bound to the exact path, size, and modification
/// time observed by Endpoint Security.
public struct ClassifiedEgressDecision: Sendable, Equatable {
    public let decisionString: String
    public let shouldAllow: Bool
    public let isCandidate: Bool
    public let requiresClassification: Bool
    public let matchingRuleId: String?
    public let policyVersion: Int
    public let channel: ClassifiedEgressChannel?
    public let classifications: [String]
    public let contentHashPrefix: String?

    public init(
        decisionString: String,
        shouldAllow: Bool,
        isCandidate: Bool,
        requiresClassification: Bool,
        matchingRuleId: String?,
        policyVersion: Int,
        channel: ClassifiedEgressChannel?,
        classifications: [String] = [],
        contentHashPrefix: String? = nil
    ) {
        self.decisionString = decisionString
        self.shouldAllow = shouldAllow
        self.isCandidate = isCandidate
        self.requiresClassification = requiresClassification
        self.matchingRuleId = matchingRuleId
        self.policyVersion = policyVersion
        self.channel = channel
        self.classifications = classifications
        self.contentHashPrefix = contentHashPrefix
    }
}
