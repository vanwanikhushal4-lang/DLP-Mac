import Foundation

public struct USBMountDecision: Sendable, Equatable {
    public let decisionString: String // "blocked", "allowed", "would-block"
    public let shouldAllowMount: Bool
    public let isUSBMountCandidate: Bool
    public let matchingRuleId: String?
    public let policyVersion: Int
    public let dispositionString: String

    public init(
        decisionString: String,
        shouldAllowMount: Bool,
        isUSBMountCandidate: Bool,
        matchingRuleId: String?,
        policyVersion: Int,
        dispositionString: String
    ) {
        self.decisionString = decisionString
        self.shouldAllowMount = shouldAllowMount
        self.isUSBMountCandidate = isUSBMountCandidate
        self.matchingRuleId = matchingRuleId
        self.policyVersion = policyVersion
        self.dispositionString = dispositionString
    }
}
