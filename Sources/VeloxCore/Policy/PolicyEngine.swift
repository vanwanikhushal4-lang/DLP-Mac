import Foundation
import os

public struct PolicyDecision: Sendable, Equatable {
    public let decisionString: String // "blocked", "allowed", "would-block"
    public let shouldAllowExecution: Bool // true for allow and would-block, false for blocked
    public let matchingRuleId: String?
    public let policyVersion: Int

    public init(
        decisionString: String,
        shouldAllowExecution: Bool,
        matchingRuleId: String?,
        policyVersion: Int
    ) {
        self.decisionString = decisionString
        self.shouldAllowExecution = shouldAllowExecution
        self.matchingRuleId = matchingRuleId
        self.policyVersion = policyVersion
    }
}

public final class PolicyEngine: @unchecked Sendable {
    private let lock = os_unfair_lock_t.allocate(capacity: 1)
    private var activePolicy: VeloxPolicy

    public init(policy: VeloxPolicy) {
        self.activePolicy = policy
        self.lock.initialize(to: os_unfair_lock())
    }

    deinit {
        lock.deallocate()
    }

    public func updatePolicy(_ newPolicy: VeloxPolicy) {
        os_unfair_lock_lock(lock)
        self.activePolicy = newPolicy
        os_unfair_lock_unlock(lock)
    }

    public func currentPolicy() -> VeloxPolicy {
        os_unfair_lock_lock(lock)
        defer { os_unfair_lock_unlock(lock) }
        return activePolicy
    }

    /// Evaluates the active policy against the intercepted process context.
    /// This method is strictly thread-safe, executes entirely in-memory,
    /// and defaults to ALLOW on any unexpected error.
    public func evaluate(process: ProcessContext) -> PolicyDecision {
        os_unfair_lock_lock(lock)
        let policy = self.activePolicy
        os_unfair_lock_unlock(lock)

        let version = policy.policyVersion
        let mode = policy.applicationControl.mode

        // 1. Critical System Guardian Check (Fail-Safe: Never block authentic macOS daemons or authentic Velox binaries)
        if SecurityGuardian.isCriticalProcess(
            signingId: process.signingId,
            teamId: process.teamId,
            executablePath: process.executablePath,
            isPlatformBinary: process.isPlatformBinary,
            codesigningFlags: process.codesigningFlags
        ) {
            return PolicyDecision(
                decisionString: "allowed",
                shouldAllowExecution: true,
                matchingRuleId: nil,
                policyVersion: version
            )
        }

        // If mode is disabled, allow everything
        if mode == .disabled {
            return PolicyDecision(
                decisionString: "allowed",
                shouldAllowExecution: true,
                matchingRuleId: nil,
                policyVersion: version
            )
        }

        // 2. Explicit Allowed Rules Check (Allow-list takes precedence)
        for rule in policy.applicationControl.allowedApplications {
            if matches(rule: rule, process: process) {
                return PolicyDecision(
                    decisionString: "allowed",
                    shouldAllowExecution: true,
                    matchingRuleId: rule.ruleId,
                    policyVersion: version
                )
            }
        }

        // 3. Blocked Rules Check
        for rule in policy.applicationControl.blockedApplications {
            if matches(rule: rule, process: process) {
                switch mode {
                case .enforce:
                    return PolicyDecision(
                        decisionString: "blocked",
                        shouldAllowExecution: false,
                        matchingRuleId: rule.ruleId,
                        policyVersion: version
                    )
                case .auditOnly:
                    return PolicyDecision(
                        decisionString: "would-block",
                        shouldAllowExecution: true,
                        matchingRuleId: rule.ruleId,
                        policyVersion: version
                    )
                case .disabled:
                    break
                }
            }
        }

        // 4. Default Allow (No matching rule)
        return PolicyDecision(
            decisionString: "allowed",
            shouldAllowExecution: true,
            matchingRuleId: nil,
            policyVersion: version
        )
    }

    private func matches(rule: ApplicationRule, process: ProcessContext) -> Bool {
        // Match Signing ID
        if let ruleSigningId = rule.signingId {
            guard let procSigningId = process.signingId,
                  procSigningId.caseInsensitiveCompare(ruleSigningId) == .orderedSame else {
                return false
            }
        }

        // Match Team ID
        if let ruleTeamId = rule.teamId {
            guard let procTeamId = process.teamId,
                  procTeamId == ruleTeamId else {
                return false
            }
        }

        // Match Platform Binary status
        if let ruleIsPlatform = rule.isPlatformBinary {
            guard process.isPlatformBinary == ruleIsPlatform else {
                return false
            }
        }

        // Match CDHash
        if let ruleCDHash = rule.cdhash {
            guard let procCDHash = process.cdhash,
                  procCDHash.caseInsensitiveCompare(ruleCDHash) == .orderedSame else {
                return false
            }
        }

        // Match exact executable path
        if let rulePath = rule.executablePath {
            guard process.executablePath == rulePath else {
                return false
            }
        }

        // Match executable path prefix
        if let rulePrefix = rule.executablePathPrefix {
            guard process.executablePath.hasPrefix(rulePrefix) else {
                return false
            }
        }

        return true
    }
}
