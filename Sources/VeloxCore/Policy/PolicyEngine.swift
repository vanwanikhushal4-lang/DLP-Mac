import Foundation
import Darwin
import os
import EndpointSecurity

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

public struct WebUploadDecision: Sendable, Equatable {
    public let decisionString: String // "blocked", "allowed", "would-block"
    public let shouldAllowOpen: Bool
    public let isUploadCandidate: Bool
    public let matchingRuleId: String?
    public let policyVersion: Int

    public init(
        decisionString: String,
        shouldAllowOpen: Bool,
        isUploadCandidate: Bool,
        matchingRuleId: String?,
        policyVersion: Int
    ) {
        self.decisionString = decisionString
        self.shouldAllowOpen = shouldAllowOpen
        self.isUploadCandidate = isUploadCandidate
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

    /// Prototype enforcement for browser file uploads.
    ///
    /// A read-only open of a regular file by a known browser/helper inside a
    /// configured user content directory is treated as an upload candidate.
    /// Write and read/write opens are deliberately allowed so an inbound browser
    /// download is never blocked by this prototype rule.
    public func evaluateWebUploadOpen(
        process: ProcessContext,
        filePath: String,
        requestedFlags: UInt32,
        isRegularFile: Bool
    ) -> WebUploadDecision {
        os_unfair_lock_lock(lock)
        let policy = self.activePolicy
        os_unfair_lock_unlock(lock)

        let version = policy.policyVersion
        let mode = policy.webUploadControl.mode
        let readRequested = (requestedFlags & UInt32(FREAD)) != 0
        let writeRequested = (requestedFlags & UInt32(FWRITE)) != 0
        let isEventOnly = (requestedFlags & UInt32(O_EVTONLY)) != 0
        let isReadOnlyData = readRequested && !writeRequested && !isEventOnly
        let isPartialDownload = Self.isBrowserPartialDownloadPath(filePath)
        let isBundleComponent = Self.isApplicationOrBundlePath(filePath)
        let isMetadata = Self.isSystemMetadataPath(filePath)

        guard mode != .disabled,
              isRegularFile,
              isReadOnlyData,
              !isPartialDownload,
              !isBundleComponent,
              !isMetadata,
              Self.isSupportedBrowser(process),
              Self.isProtectedUserContentPath(
                  filePath,
                  directoryNames: policy.webUploadControl.protectedDirectoryNames
              ) else {
            return WebUploadDecision(
                decisionString: "allowed",
                shouldAllowOpen: true,
                isUploadCandidate: false,
                matchingRuleId: nil,
                policyVersion: version
            )
        }

        switch mode {
        case .enforce:
            return WebUploadDecision(
                decisionString: "blocked",
                shouldAllowOpen: false,
                isUploadCandidate: true,
                matchingRuleId: "browser-file-upload",
                policyVersion: version
            )
        case .auditOnly:
            return WebUploadDecision(
                decisionString: "would-block",
                shouldAllowOpen: true,
                isUploadCandidate: true,
                matchingRuleId: "browser-file-upload",
                policyVersion: version
            )
        case .disabled:
            return WebUploadDecision(
                decisionString: "allowed",
                shouldAllowOpen: true,
                isUploadCandidate: false,
                matchingRuleId: nil,
                policyVersion: version
            )
        }
    }

    /// Evaluates clipboard content file references against protected directories.
    public func evaluateClipboardContent(filePaths: [String]) -> ClipboardDecision {
        os_unfair_lock_lock(lock)
        let policy = self.activePolicy
        os_unfair_lock_unlock(lock)

        let version = policy.policyVersion
        let mode = policy.webUploadControl.mode

        guard mode != .disabled else {
            return ClipboardDecision(
                decisionString: "allowed",
                shouldBlock: false,
                blockedPaths: [],
                matchingRuleId: nil,
                policyVersion: version
            )
        }

        let protected = filePaths.filter { path in
            Self.isProtectedUserContentPath(
                path,
                directoryNames: policy.webUploadControl.protectedDirectoryNames
            )
        }

        guard !protected.isEmpty else {
            return ClipboardDecision(
                decisionString: "allowed",
                shouldBlock: false,
                blockedPaths: [],
                matchingRuleId: nil,
                policyVersion: version
            )
        }

        switch mode {
        case .enforce:
            return ClipboardDecision(
                decisionString: "blocked",
                shouldBlock: true,
                blockedPaths: protected,
                matchingRuleId: "clipboard-file-transfer",
                policyVersion: version
            )
        case .auditOnly:
            return ClipboardDecision(
                decisionString: "would-block",
                shouldBlock: false,
                blockedPaths: protected,
                matchingRuleId: "clipboard-file-transfer",
                policyVersion: version
            )
        case .disabled:
            return ClipboardDecision(
                decisionString: "allowed",
                shouldBlock: false,
                blockedPaths: [],
                matchingRuleId: nil,
                policyVersion: version
            )
        }
    }

    /// Evaluates a filesystem mount event for USB / removable media protection.
    public func evaluateMount(
        process: ProcessContext,
        mountFrom: String,
        mountPoint: String,
        fsType: String,
        disposition: es_mount_disposition_t
    ) -> USBMountDecision {
        os_unfair_lock_lock(lock)
        let policy = self.activePolicy
        os_unfair_lock_unlock(lock)

        let version = policy.policyVersion
        let config = policy.usbStorageControl
        let mode = config.mode

        let dispositionStr: String
        switch disposition {
        case ES_MOUNT_DISPOSITION_EXTERNAL: dispositionStr = "external"
        case ES_MOUNT_DISPOSITION_INTERNAL: dispositionStr = "internal"
        case ES_MOUNT_DISPOSITION_NETWORK: dispositionStr = "network"
        case ES_MOUNT_DISPOSITION_VIRTUAL: dispositionStr = "virtual"
        case ES_MOUNT_DISPOSITION_NULLFS: dispositionStr = "nullfs"
        default: dispositionStr = "unknown"
        }

        // CRITICAL INVARIANT: NEVER block internal system storage or nullfs/app translocation.
        guard disposition == ES_MOUNT_DISPOSITION_EXTERNAL else {
            return USBMountDecision(
                decisionString: "allowed",
                shouldAllowMount: true,
                isUSBMountCandidate: false,
                matchingRuleId: nil,
                policyVersion: version,
                dispositionString: dispositionStr
            )
        }

        guard mode != .disabled, config.blockExternalStorage else {
            return USBMountDecision(
                decisionString: "allowed",
                shouldAllowMount: true,
                isUSBMountCandidate: true,
                matchingRuleId: nil,
                policyVersion: version,
                dispositionString: dispositionStr
            )
        }

        switch mode {
        case .enforce:
            return USBMountDecision(
                decisionString: "blocked",
                shouldAllowMount: false,
                isUSBMountCandidate: true,
                matchingRuleId: "usb-storage-block-external",
                policyVersion: version,
                dispositionString: dispositionStr
            )
        case .auditOnly:
            return USBMountDecision(
                decisionString: "would-block",
                shouldAllowMount: true,
                isUSBMountCandidate: true,
                matchingRuleId: "usb-storage-audit-external",
                policyVersion: version,
                dispositionString: dispositionStr
            )
        case .disabled:
            return USBMountDecision(
                decisionString: "allowed",
                shouldAllowMount: true,
                isUSBMountCandidate: false,
                matchingRuleId: nil,
                policyVersion: version,
                dispositionString: dispositionStr
            )
        }
    }

    public static func isSupportedBrowserBundleId(_ bundleId: String) -> Bool {
        let lower = bundleId.lowercased()
        let prefixes = [
            "com.apple.safari",
            "com.apple.webkit.webcontent",
            "com.apple.webkit.networking",
            "com.google.chrome",
            "com.microsoft.edgemac",
            "com.brave.browser",
            "org.mozilla.firefox",
            "com.operasoftware.opera",
            "company.thebrowser.browser"
        ]
        return prefixes.contains(where: { lower == $0 || lower.hasPrefix($0 + ".") })
    }

    private static func isSupportedBrowser(_ process: ProcessContext) -> Bool {
        let signingId = process.signingId?.lowercased() ?? ""
        if isSupportedBrowserBundleId(signingId) {
            return true
        }

        let executablePath = process.executablePath.lowercased()
        let appPathMarkers = [
            "/safari.app/",
            "/google chrome.app/",
            "/microsoft edge.app/",
            "/brave browser.app/",
            "/firefox.app/",
            "/opera.app/",
            "/arc.app/"
        ]
        return appPathMarkers.contains(where: executablePath.contains)
    }

    public static func isProtectedUserContentPath(
        _ filePath: String,
        directoryNames: [String]
    ) -> Bool {
        let components = URL(fileURLWithPath: filePath).resolvingSymlinksInPath().standardizedFileURL.pathComponents
        guard components.count >= 5,
              components[0] == "/",
              components[1] == "Users",
              !components[2].isEmpty else {
            return false
        }

        let protectedNames = Set(directoryNames.map { $0.lowercased() })
        return protectedNames.contains(components[3].lowercased())
    }

    private static func isBrowserPartialDownloadPath(_ filePath: String) -> Bool {
        let lowercasedPath = filePath.lowercased()
        return lowercasedPath.hasSuffix(".crdownload") ||
            lowercasedPath.hasSuffix(".download") ||
            lowercasedPath.hasSuffix(".part") ||
            lowercasedPath.hasSuffix(".partial")
    }

    private static func isApplicationOrBundlePath(_ filePath: String) -> Bool {
        let lower = filePath.lowercased()
        let bundleMarkers = [
            ".app/",
            ".appex/",
            ".framework/",
            ".bundle/",
            ".plugin/",
            ".xpc/"
        ]
        return bundleMarkers.contains(where: lower.contains)
    }

    private static func isSystemMetadataPath(_ filePath: String) -> Bool {
        let name = URL(fileURLWithPath: filePath).lastPathComponent.lowercased()
        return name == ".ds_store" || name == ".localized" || name.hasPrefix("icon\r")
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

        // Match executable path prefix with strict directory boundary safety
        if let rulePrefix = rule.executablePathPrefix {
            let prefixWithSlash = rulePrefix.hasSuffix("/") ? rulePrefix : rulePrefix + "/"
            guard process.executablePath == rulePrefix || process.executablePath.hasPrefix(prefixWithSlash) else {
                return false
            }
        }

        return true
    }
}
