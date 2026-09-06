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

    /// Evaluates outbound file reads made by AirDrop and Bluetooth transfer services.
    /// The rule intentionally denies read-only access to protected user files while
    /// allowing write access used by incoming transfers.
    public func evaluateNearbyTransferOpen(
        process: ProcessContext,
        filePath: String,
        requestedFlags: UInt32,
        isRegularFile: Bool
    ) -> NearbyTransferDecision {
        os_unfair_lock_lock(lock)
        let policy = self.activePolicy
        os_unfair_lock_unlock(lock)

        let version = policy.policyVersion
        let config = policy.nearbyTransferControl
        let readRequested = (requestedFlags & UInt32(FREAD)) != 0
        let writeRequested = (requestedFlags & UInt32(FWRITE)) != 0
        let isEventOnly = (requestedFlags & UInt32(O_EVTONLY)) != 0
        let isReadOnlyData = readRequested && !writeRequested && !isEventOnly
        let channel = Self.nearbyTransferChannel(process)

        let channelEnabled: Bool
        switch channel {
        case "airdrop", "apple-sharing":
            channelEnabled = config.blockAirDrop
        case "bluetooth":
            channelEnabled = config.blockBluetoothFileTransfer
        default:
            channelEnabled = false
        }

        guard config.mode != .disabled,
              channelEnabled,
              isRegularFile,
              isReadOnlyData,
              !Self.isBrowserPartialDownloadPath(filePath),
              !Self.isApplicationOrBundlePath(filePath),
              !Self.isSystemMetadataPath(filePath),
              Self.isProtectedUserContentPath(
                  filePath,
                  directoryNames: config.protectedDirectoryNames
              ) else {
            return NearbyTransferDecision(
                decisionString: "allowed",
                shouldAllowOpen: true,
                isTransferCandidate: false,
                matchingRuleId: nil,
                policyVersion: version,
                channel: channel
            )
        }

        let ruleId = channel == "bluetooth"
            ? "nearby-bluetooth-file-read"
            : "nearby-airdrop-file-read"

        switch config.mode {
        case .enforce:
            return NearbyTransferDecision(
                decisionString: "blocked",
                shouldAllowOpen: false,
                isTransferCandidate: true,
                matchingRuleId: ruleId,
                policyVersion: version,
                channel: channel
            )
        case .auditOnly:
            return NearbyTransferDecision(
                decisionString: "would-block",
                shouldAllowOpen: true,
                isTransferCandidate: true,
                matchingRuleId: ruleId,
                policyVersion: version,
                channel: channel
            )
        case .disabled:
            return NearbyTransferDecision(
                decisionString: "allowed",
                shouldAllowOpen: true,
                isTransferCandidate: false,
                matchingRuleId: nil,
                policyVersion: version,
                channel: channel
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

    /// Evaluates a newly copied clipboard item against the configured source-app
    /// policy. The host agent supplies a code-signing-derived process identity.
    public func evaluateClipboardCopy(source process: ProcessContext) -> ClipboardControlDecision {
        os_unfair_lock_lock(lock)
        let policy = self.activePolicy
        os_unfair_lock_unlock(lock)

        let version = policy.policyVersion
        let config = policy.clipboardControl

        switch config.mode {
        case .disabled:
            return ClipboardControlDecision(
                decisionString: "allowed",
                shouldClearPasteboard: false,
                matchingRuleId: nil,
                policyVersion: version
            )

        case .blockAll:
            return ClipboardControlDecision(
                decisionString: "blocked",
                shouldClearPasteboard: true,
                matchingRuleId: "clipboard-block-all",
                policyVersion: version
            )

        case .blockSelectedApplications:
            for rule in config.blockedApplications where matches(rule: rule, process: process) {
                return ClipboardControlDecision(
                    decisionString: "blocked",
                    shouldClearPasteboard: true,
                    matchingRuleId: rule.ruleId,
                    policyVersion: version
                )
            }
            return ClipboardControlDecision(
                decisionString: "allowed",
                shouldClearPasteboard: false,
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

        // Encrypted-container mode must allow the physical device to mount so
        // the privileged coordinator can provision and attach its AES-256
        // sparse bundle. Plaintext writes to this outer mount are authorized
        // separately by USBEncryptionAccessController.
        if config.encryptionMode != .disabled {
            return USBMountDecision(
                decisionString: config.encryptionMode == .auditOnly ? "would-encrypt" : "allowed",
                shouldAllowMount: true,
                isUSBMountCandidate: true,
                matchingRuleId: config.encryptionMode == .auditOnly
                    ? "usb-encryption-container-audit"
                    : "usb-encryption-container-required",
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

    public static func nearbyTransferChannel(_ process: ProcessContext) -> String? {
        let signingId = process.signingId?.lowercased() ?? ""
        let executablePath = process.executablePath.lowercased()

        if signingId == "com.apple.sharingd" ||
            executablePath == "/usr/libexec/sharingd" {
            // sharingd is used by AirDrop and by other Apple Share Sheet routes.
            // Endpoint Security exposes the reading process, not the selected UI destination,
            // so keep this attribution honest in events and notifications.
            return "apple-sharing"
        }

        if signingId == "com.apple.finder.open-airdrop" ||
            executablePath.contains("/airdrop.app/") {
            return "airdrop"
        }

        if signingId == "com.apple.bluetoothfileexchange" ||
            signingId == "com.apple.obexagent" ||
            executablePath.contains("/bluetooth file exchange.app/") ||
            executablePath.contains("/obexagent.app/") {
            return "bluetooth"
        }

        return nil
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

    /// Evaluates an outbound network flow against active Network Flow Control policies.
    /// Fail-open: unexpected errors or disabled state return an allowed decision.
    public func evaluateNetworkFlow(_ context: NetworkFlowContext) -> NetworkFlowDecision {
        os_unfair_lock_lock(lock)
        let policy = self.activePolicy
        os_unfair_lock_unlock(lock)

        let version = policy.policyVersion
        let config = policy.networkFlowControl
        let mode = config.mode

        // 1. Critical System Guardian Check (Fail-Safe: Never block authentic macOS daemons or authentic Velox binaries)
        if SecurityGuardian.isCriticalProcess(
            signingId: context.process.signingId,
            teamId: context.process.teamId,
            executablePath: context.process.executablePath,
            isPlatformBinary: context.process.isPlatformBinary,
            codesigningFlags: context.process.codesigningFlags
        ) {
            return NetworkFlowDecision(
                decisionString: "allowed",
                shouldAllowFlow: true,
                matchingRuleId: nil,
                policyVersion: version
            )
        }

        // 2. Direction check - only inspect outbound connections
        guard context.isOutbound else {
            return NetworkFlowDecision(
                decisionString: "allowed",
                shouldAllowFlow: true,
                matchingRuleId: nil,
                policyVersion: version
            )
        }

        // A default-block policy must never turn an attribution failure into a
        // system-wide outage. If NetworkExtension cannot identify the source
        // process at all, fail open and wait for a future fully attributed flow.
        guard context.process.pid > 0,
              context.process.executablePath != "unknown" else {
            return NetworkFlowDecision(
                decisionString: "allowed",
                shouldAllowFlow: true,
                matchingRuleId: nil,
                policyVersion: version
            )
        }

        // 3. Disabled mode
        if mode == .disabled {
            return NetworkFlowDecision(
                decisionString: "allowed",
                shouldAllowFlow: true,
                matchingRuleId: nil,
                policyVersion: version
            )
        }

        // 4. Evaluate Explicit Rules: Allow rules take absolute precedence over Block rules
        let allowRules = config.rules.filter { $0.action == "allow" }
        for rule in allowRules {
            if matchesNetworkRule(rule, context: context) {
                return NetworkFlowDecision(
                    decisionString: "allowed",
                    shouldAllowFlow: true,
                    matchingRuleId: rule.ruleId,
                    policyVersion: version
                )
            }
        }

        let blockRules = config.rules.filter { $0.action == "block" }
        for rule in blockRules {
            if matchesNetworkRule(rule, context: context) {
                switch mode {
                case .enforce:
                    return NetworkFlowDecision(
                        decisionString: "blocked",
                        shouldAllowFlow: false,
                        matchingRuleId: rule.ruleId,
                        policyVersion: version
                    )
                case .auditOnly:
                    return NetworkFlowDecision(
                        decisionString: "would-block",
                        shouldAllowFlow: true,
                        matchingRuleId: rule.ruleId,
                        policyVersion: version
                    )
                case .disabled:
                    break
                }
            }
        }

        // 5. Default Action if no explicit rule matched
        switch config.defaultAction {
        case .allow:
            return NetworkFlowDecision(
                decisionString: "allowed",
                shouldAllowFlow: true,
                matchingRuleId: nil,
                policyVersion: version
            )
        case .block:
            switch mode {
            case .enforce:
                return NetworkFlowDecision(
                    decisionString: "blocked",
                    shouldAllowFlow: false,
                    matchingRuleId: "network-flow-default-block",
                    policyVersion: version
                )
            case .auditOnly:
                return NetworkFlowDecision(
                    decisionString: "would-block",
                    shouldAllowFlow: true,
                    matchingRuleId: "network-flow-default-block",
                    policyVersion: version
                )
            case .disabled:
                return NetworkFlowDecision(
                    decisionString: "allowed",
                    shouldAllowFlow: true,
                    matchingRuleId: nil,
                    policyVersion: version
                )
            }
        }
    }

    private func matchesNetworkRule(_ rule: NetworkDestinationRule, context: NetworkFlowContext) -> Bool {
        // Match process if specified
        if let procRule = rule.process {
            guard matches(rule: procRule, process: context.process) else {
                return false
            }
        }

        // Match protocol if specified
        guard NetworkMatcher.matchesProtocol(ruleProtocol: rule.protocol, flowProtocol: context.networkProtocol) else {
            return false
        }

        // Match port / port range if specified
        if rule.port != nil || rule.portRange != nil {
            guard NetworkMatcher.matchesPort(singlePort: rule.port, portRange: rule.portRange, flowPort: context.remotePort) else {
                return false
            }
        }

        // Match destination address / domain if specified
        let hasHostOrIPRule = rule.domain != nil || rule.ipAddress != nil || rule.cidrRange != nil
        if hasHostOrIPRule {
            var matchedDestination = false

            if let domainPattern = rule.domain, let host = context.remoteHostname {
                if NetworkMatcher.matchesDomain(pattern: domainPattern, hostname: host) {
                    matchedDestination = true
                }
            }

            if !matchedDestination, let ruleIP = rule.ipAddress, let flowIP = context.remoteAddress {
                if NetworkMatcher.matchesIP(ruleIP: ruleIP, flowIP: flowIP) {
                    matchedDestination = true
                }
            }

            if !matchedDestination, let cidr = rule.cidrRange, let flowIP = context.remoteAddress {
                if NetworkMatcher.matchesCIDR(cidr: cidr, flowIP: flowIP) {
                    matchedDestination = true
                }
            }

            guard matchedDestination else {
                return false
            }
        }

        return true
    }
}
