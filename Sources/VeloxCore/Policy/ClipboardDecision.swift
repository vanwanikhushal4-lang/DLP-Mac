import Foundation

public struct ClipboardDecision: Sendable, Equatable {
    public let decisionString: String // "blocked", "allowed", "would-block"
    public let shouldBlock: Bool
    public let blockedPaths: [String]
    public let matchingRuleId: String?
    public let policyVersion: Int

    public init(
        decisionString: String,
        shouldBlock: Bool,
        blockedPaths: [String],
        matchingRuleId: String?,
        policyVersion: Int
    ) {
        self.decisionString = decisionString
        self.shouldBlock = shouldBlock
        self.blockedPaths = blockedPaths
        self.matchingRuleId = matchingRuleId
        self.policyVersion = policyVersion
    }
}
