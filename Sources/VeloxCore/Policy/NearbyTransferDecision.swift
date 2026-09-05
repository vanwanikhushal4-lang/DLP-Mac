import Foundation

public struct NearbyTransferDecision: Sendable, Equatable {
    public let decisionString: String
    public let shouldAllowOpen: Bool
    public let isTransferCandidate: Bool
    public let matchingRuleId: String?
    public let policyVersion: Int
    public let channel: String?

    public init(
        decisionString: String,
        shouldAllowOpen: Bool,
        isTransferCandidate: Bool,
        matchingRuleId: String?,
        policyVersion: Int,
        channel: String?
    ) {
        self.decisionString = decisionString
        self.shouldAllowOpen = shouldAllowOpen
        self.isTransferCandidate = isTransferCandidate
        self.matchingRuleId = matchingRuleId
        self.policyVersion = policyVersion
        self.channel = channel
    }
}
