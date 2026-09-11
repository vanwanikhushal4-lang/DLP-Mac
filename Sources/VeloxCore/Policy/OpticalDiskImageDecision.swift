import Foundation

public enum OpticalMountKind: String, Codable, Sendable, Equatable {
    case diskImage = "disk-image"
    case opticalMedia = "optical-media"
}

/// Result of evaluating a virtual disk-image or physical optical-media mount.
/// The decision is intentionally metadata-only and safe to evaluate inside an
/// Endpoint Security authorization deadline.
public struct OpticalDiskImageDecision: Sendable, Equatable {
    public let decisionString: String
    public let shouldAllowMount: Bool
    public let isCandidate: Bool
    public let matchingRuleId: String?
    public let policyVersion: Int
    public let mountKind: OpticalMountKind?

    public init(
        decisionString: String,
        shouldAllowMount: Bool,
        isCandidate: Bool,
        matchingRuleId: String?,
        policyVersion: Int,
        mountKind: OpticalMountKind?
    ) {
        self.decisionString = decisionString
        self.shouldAllowMount = shouldAllowMount
        self.isCandidate = isCandidate
        self.matchingRuleId = matchingRuleId
        self.policyVersion = policyVersion
        self.mountKind = mountKind
    }
}
