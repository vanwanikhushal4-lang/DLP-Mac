import Foundation

public struct NetworkFlowContext: Sendable {
    public let process: ProcessContext
    public let remoteHostname: String?
    public let remoteAddress: String?
    public let remotePort: Int
    public let networkProtocol: NetworkProtocol
    public let isOutbound: Bool

    public init(
        process: ProcessContext,
        remoteHostname: String? = nil,
        remoteAddress: String? = nil,
        remotePort: Int,
        networkProtocol: NetworkProtocol = .tcp,
        ipProtocol: NetworkProtocol? = nil,
        isOutbound: Bool = true
    ) {
        self.process = process
        self.remoteHostname = remoteHostname
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.networkProtocol = ipProtocol ?? networkProtocol
        self.isOutbound = isOutbound
    }
}

public struct NetworkFlowDecision: Sendable, Equatable {
    public let decisionString: String // "allowed", "blocked", "would-block"
    public let shouldAllowFlow: Bool
    public let matchingRuleId: String?
    public let policyVersion: Int

    public init(
        decisionString: String,
        shouldAllowFlow: Bool,
        matchingRuleId: String?,
        policyVersion: Int
    ) {
        self.decisionString = decisionString
        self.shouldAllowFlow = shouldAllowFlow
        self.matchingRuleId = matchingRuleId
        self.policyVersion = policyVersion
    }
}
