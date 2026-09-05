import Foundation
import EndpointSecurity
import Darwin
import os

public enum EndpointSecurityError: Error, CustomStringConvertible, Sendable {
    case initializationFailed(String)
    case subscriptionFailed(String)
    case fullDiskAccessRequired
    case entitlementMissing
    case rootPrivilegesRequired
    case tooManyClients
    case unknown(UInt32)

    public var description: String {
        switch self {
        case .initializationFailed(let msg): return "Init failed: \(msg)"
        case .subscriptionFailed(let msg): return "Subscription failed: \(msg)"
        case .fullDiskAccessRequired: return "Full Disk Access (TCC) is required to run the Endpoint Security extension."
        case .entitlementMissing: return "Endpoint Security entitlement ('com.apple.developer.endpoint-security.client') is missing or rejected."
        case .rootPrivilegesRequired: return "Endpoint Security requires root privileges (UID 0)."
        case .tooManyClients: return "System has reached maximum concurrent Endpoint Security clients."
        case .unknown(let code): return "es_new_client failed with error code: \(code)"
        }
    }
}

public struct HealthStatus: Codable, Sendable {
    public let status: String // "enforcing", "unhealthy", "stopped"
    public let lastStarted: String
    public let subscribedEvents: [String]
    public let lastError: String?
    public let totalAuthHandled: UInt64
    public let totalDeadlineMisses: UInt64
}

public final class EndpointSecurityService: @unchecked Sendable {
    public private(set) var client: OpaquePointer?
    private let policyEngine: PolicyEngine
    private let logger: EventLogger
    private let healthPath: String

    private let stateLock = os_unfair_lock_t.allocate(capacity: 1)
    private var isRunning: Bool = false
    private var totalAuthHandled: UInt64 = 0
    private var totalDeadlineMisses: UInt64 = 0
    private var lastError: String? = nil
    private var startTimeString: String = ""
    private var eventBlockedHandler: (@Sendable (ExecutionEvent) -> Void)?

    public var onEventBlocked: (@Sendable (ExecutionEvent) -> Void)? {
        get {
            os_unfair_lock_lock(stateLock)
            defer { os_unfair_lock_unlock(stateLock) }
            return eventBlockedHandler
        }
        set {
            os_unfair_lock_lock(stateLock)
            eventBlockedHandler = newValue
            os_unfair_lock_unlock(stateLock)
        }
    }

    private func notifyBlockedIfHandlerPresent(_ event: ExecutionEvent) {
        os_unfair_lock_lock(stateLock)
        let handler = eventBlockedHandler
        os_unfair_lock_unlock(stateLock)
        handler?(event)
    }

    public init(
        policyEngine: PolicyEngine,
        logger: EventLogger,
        healthPath: String = "/Library/Application Support/VeloxMacDLP/health.json"
    ) {
        self.policyEngine = policyEngine
        self.logger = logger
        self.healthPath = healthPath
        self.stateLock.initialize(to: os_unfair_lock())
    }

    deinit {
        stop()
        stateLock.deallocate()
    }

    /// Connects to the Endpoint Security subsystem with bounded retries.
    public func start(maxRetries: Int = 3) -> Result<Void, EndpointSecurityError> {
        var attempts = 0
        var lastErr: EndpointSecurityError = .initializationFailed("Unknown error")

        while attempts <= maxRetries {
            let attemptResult = attemptStart()
            switch attemptResult {
            case .success:
                writeHealthRecord(status: "enforcing", error: nil)
                return .success(())
            case .failure(let error):
                lastErr = error
                attempts += 1
                if attempts <= maxRetries {
                    let backoff = UInt32(pow(2.0, Double(attempts - 1)))
                    fputs("[VeloxEndpointSecurityService] Start attempt \(attempts) failed (\(error)). Retrying in \(backoff)s...\n", stderr)
                    sleep(backoff)
                }
            }
        }

        writeHealthRecord(status: "unhealthy", error: lastErr.description)
        return .failure(lastErr)
    }

    private func attemptStart() -> Result<Void, EndpointSecurityError> {
        guard client == nil else {
            return .success(())
        }

        var newClient: OpaquePointer?
        // Guarantee: strong reference fallback ensures every auth event is answered even during dealloc
        let result = es_new_client(&newClient) { [weak self] (esClient, messagePointer) in
            if let strongSelf = self {
                strongSelf.handleMessage(client: esClient, message: messagePointer)
            } else {
                // Fail-safe guaranteed response: Never leave kernel waiting. AUTH_OPEN
                // is the sole ES auth event that requires a flags response.
                if messagePointer.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN {
                    _ = es_respond_flags_result(esClient, messagePointer, UInt32.max, false)
                } else {
                    _ = es_respond_auth_result(esClient, messagePointer, ES_AUTH_RESULT_ALLOW, false)
                }
            }
        }

        switch result {
        case ES_NEW_CLIENT_RESULT_SUCCESS:
            self.client = newClient
            self.isRunning = true
            let formatter = ISO8601DateFormatter()
            self.startTimeString = formatter.string(from: Date())

            // AUTH_EXEC enforces application control.
            // AUTH_OPEN enforces web upload control.
            // AUTH_MOUNT & AUTH_REMOUNT enforce USB / removable media protection.
            // NOTIFY_UNMOUNT audits removable device disconnects.
            var events = [
                ES_EVENT_TYPE_AUTH_EXEC,
                ES_EVENT_TYPE_AUTH_OPEN,
                ES_EVENT_TYPE_AUTH_MOUNT,
                ES_EVENT_TYPE_AUTH_REMOUNT,
                ES_EVENT_TYPE_NOTIFY_UNMOUNT
            ]
            let subResult = es_subscribe(newClient!, &events, UInt32(events.count))
            if subResult != ES_RETURN_SUCCESS {
                let err = "Failed to subscribe to ES events: \(subResult.rawValue)"
                stop()
                return .failure(.subscriptionFailed(err))
            }

            return .success(())

        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            return .failure(.fullDiskAccessRequired)
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            return .failure(.entitlementMissing)
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            return .failure(.rootPrivilegesRequired)
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            return .failure(.tooManyClients)
        default:
            return .failure(.unknown(result.rawValue))
        }
    }

    public func stop() {
        if let cl = client {
            es_unsubscribe_all(cl)
            es_delete_client(cl)
            self.client = nil
            self.isRunning = false
            writeHealthRecord(status: "stopped", error: nil)
        }
    }

    public func clearCache() {
        guard let cl = client else { return }
        let res = es_clear_cache(cl)
        if res != ES_CLEAR_CACHE_RESULT_SUCCESS {
            fputs("[VeloxEndpointSecurityService] es_clear_cache failed: \(res.rawValue)\n", stderr)
        }
    }

    /// Handles an incoming Endpoint Security message with absolute response guarantee.
    /// Invariants enforced:
    /// 1. Exactly one response is issued for every AUTH event.
    /// 2. Caching is disabled (cache = false) so every execution attempt triggers a log event.
    /// 3. Return value of es_respond_auth_result is validated and logged.
    /// 4. Kernel deadlines are checked and tracked.
    /// 5. Async log dispatch prevents disk latency in the kernel thread.
    public func handleMessage(client: OpaquePointer, message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        guard msg.action_type == ES_ACTION_TYPE_AUTH else {
            return
        }

        let startNs = DispatchTime.now().uptimeNanoseconds

        // Check deadline
        let deadline = msg.deadline
        if deadline != 0 && mach_absolute_time() >= deadline {
            os_unfair_lock_lock(stateLock)
            totalDeadlineMisses += 1
            os_unfair_lock_unlock(stateLock)
            fputs("[VeloxEndpointSecurityService] WARNING: Message deadline already passed before processing!\n", stderr)
        }

        os_unfair_lock_lock(stateLock)
        totalAuthHandled += 1
        os_unfair_lock_unlock(stateLock)

        if msg.event_type == ES_EVENT_TYPE_AUTH_EXEC {
            let target = msg.event.exec.target.pointee
            let procContext = extractProcessContext(target: target)

            // In-memory policy evaluation (sub-millisecond)
            let decision = policyEngine.evaluate(process: procContext)

            let endNs = DispatchTime.now().uptimeNanoseconds
            let latencyMicros = max(1, UInt64((endNs - startNs) / 1000))

            let authResult: es_auth_result_t = decision.shouldAllowExecution ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY

            // Guaranteed response: caching disabled (cache = false) so every attempt generates an event
            let res = es_respond_auth_result(client, message, authResult, false)
            let responseStatus = (res == ES_RESPOND_RESULT_SUCCESS) ? "success" : "failed_code_\(res.rawValue)"
            if res != ES_RESPOND_RESULT_SUCCESS {
                fputs("[VeloxEndpointSecurityService] CRITICAL: es_respond_auth_result failed with result: \(res.rawValue)\n", stderr)
            }

            // Construct and enqueue structured JSONL event asynchronously
            let event = ExecutionEvent(
                timestamp: nil,
                eventId: UUID().uuidString,
                module: "application-control",
                action: "exec",
                decision: decision.decisionString,
                ruleId: decision.matchingRuleId,
                policyVersion: decision.policyVersion,
                executablePath: procContext.executablePath,
                signingId: procContext.signingId,
                teamId: procContext.teamId,
                pid: procContext.pid,
                parentPid: procContext.parentPid,
                uid: procContext.uid,
                decisionLatencyMicros: latencyMicros,
                authResponseResult: responseStatus
            )
            logger.logEventAsync(event)
            if decision.decisionString == "blocked" {
                notifyBlockedIfHandlerPresent(event)
            }
        } else if msg.event_type == ES_EVENT_TYPE_AUTH_OPEN {
            handleOpenMessage(
                client: client,
                message: message,
                startNs: startNs
            )
        } else if msg.event_type == ES_EVENT_TYPE_AUTH_MOUNT {
            handleMountMessage(
                client: client,
                message: message,
                startNs: startNs
            )
        } else if msg.event_type == ES_EVENT_TYPE_AUTH_REMOUNT {
            handleRemountMessage(
                client: client,
                message: message,
                startNs: startNs
            )
        } else if msg.event_type == ES_EVENT_TYPE_NOTIFY_UNMOUNT {
            handleUnmountMessage(
                message: message
            )
        } else {
            // Guarantee: always respond to any other unhandled AUTH event with ALLOW
            let res = es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
            if res != ES_RESPOND_RESULT_SUCCESS {
                fputs("[VeloxEndpointSecurityService] es_respond_auth_result failed on fallback: \(res.rawValue)\n", stderr)
            }
        }
    }

    private func handleOpenMessage(
        client: OpaquePointer,
        message: UnsafePointer<es_message_t>,
        startNs: UInt64
    ) {
        let msg = message.pointee
        let actor = msg.process.pointee
        let file = msg.event.open.file.pointee
        let process = extractProcessContext(target: actor)
        let filePath = stringFromToken(file.path) ?? ""
        let requestedFlags = UInt32(bitPattern: msg.event.open.fflag)
        let fileType = file.stat.st_mode & mode_t(S_IFMT)
        let isRegularFile = fileType == mode_t(S_IFREG)

        let decision = policyEngine.evaluateWebUploadOpen(
            process: process,
            filePath: filePath,
            requestedFlags: requestedFlags,
            isRegularFile: isRegularFile
        )

        let allowedFlags: UInt32 = decision.shouldAllowOpen ? UInt32.max : 0
        let response = es_respond_flags_result(client, message, allowedFlags, false)
        let responseStatus = response == ES_RESPOND_RESULT_SUCCESS
            ? "success"
            : "failed_code_\(response.rawValue)"

        if response != ES_RESPOND_RESULT_SUCCESS {
            fputs(
                "[VeloxEndpointSecurityService] CRITICAL: AUTH_OPEN response failed: \(response.rawValue)\n",
                stderr
            )
        }

        // AUTH_OPEN is extremely high-volume. Persist only relevant upload
        // candidates; unrelated browser and system file opens are not logged.
        guard decision.isUploadCandidate else { return }

        let endNs = DispatchTime.now().uptimeNanoseconds
        let latencyMicros = max(1, UInt64((endNs - startNs) / 1_000))
        let event = ExecutionEvent(
            timestamp: nil,
            eventId: UUID().uuidString,
            module: "web-upload-control",
            action: "browser-file-open",
            decision: decision.decisionString,
            ruleId: decision.matchingRuleId,
            policyVersion: decision.policyVersion,
            executablePath: process.executablePath,
            signingId: process.signingId,
            teamId: process.teamId,
            pid: process.pid,
            parentPid: process.parentPid,
            uid: process.uid,
            decisionLatencyMicros: latencyMicros,
            authResponseResult: responseStatus,
            resourcePath: filePath,
            requestedOpenFlags: requestedFlags
        )
        logger.logEventAsync(event)
        if decision.decisionString == "blocked" {
            notifyBlockedIfHandlerPresent(event)
        }
    }

    private func handleMountMessage(
        client: OpaquePointer,
        message: UnsafePointer<es_message_t>,
        startNs: UInt64
    ) {
        let msg = message.pointee
        let actor = msg.process.pointee
        let process = extractProcessContext(target: actor)
        let mountEvent = msg.event.mount
        var sfs = mountEvent.statfs.pointee
        let disposition = mountEvent.disposition

        let mountFrom = withUnsafePointer(to: &sfs.f_mntfromname) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MNAMELEN)) { cStr in
                String(cString: cStr)
            }
        }
        let mountPoint = withUnsafePointer(to: &sfs.f_mntonname) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MNAMELEN)) { cStr in
                String(cString: cStr)
            }
        }
        let fsType = withUnsafePointer(to: &sfs.f_fstypename) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MFSNAMELEN)) { cStr in
                String(cString: cStr)
            }
        }

        let decision = policyEngine.evaluateMount(
            process: process,
            mountFrom: mountFrom,
            mountPoint: mountPoint,
            fsType: fsType,
            disposition: disposition
        )

        let authResult: es_auth_result_t = decision.shouldAllowMount ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
        let response = es_respond_auth_result(client, message, authResult, false)
        let responseStatus = response == ES_RESPOND_RESULT_SUCCESS ? "success" : "failed_code_\(response.rawValue)"

        guard decision.isUSBMountCandidate else { return }
 
        let endNs = DispatchTime.now().uptimeNanoseconds
        let latencyMicros = max(1, UInt64((endNs - startNs) / 1_000))
        let event = ExecutionEvent(
            timestamp: nil,
            eventId: UUID().uuidString,
            module: "usb-storage-control",
            action: "mount",
            decision: decision.decisionString,
            ruleId: decision.matchingRuleId,
            policyVersion: decision.policyVersion,
            executablePath: process.executablePath,
            signingId: process.signingId,
            teamId: process.teamId,
            pid: process.pid,
            parentPid: process.parentPid,
            uid: process.uid,
            decisionLatencyMicros: latencyMicros,
            authResponseResult: responseStatus,
            resourcePath: "\(mountFrom) -> \(mountPoint) (\(fsType))"
        )
        logger.logEventAsync(event)
        if decision.decisionString == "blocked" {
            notifyBlockedIfHandlerPresent(event)
        }
    }

    private func handleRemountMessage(
        client: OpaquePointer,
        message: UnsafePointer<es_message_t>,
        startNs: UInt64
    ) {
        let msg = message.pointee
        let actor = msg.process.pointee
        let process = extractProcessContext(target: actor)
        let remountEvent = msg.event.remount
        var sfs = remountEvent.statfs.pointee
        let disposition = remountEvent.disposition

        let mountFrom = withUnsafePointer(to: &sfs.f_mntfromname) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MNAMELEN)) { cStr in
                String(cString: cStr)
            }
        }
        let mountPoint = withUnsafePointer(to: &sfs.f_mntonname) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MNAMELEN)) { cStr in
                String(cString: cStr)
            }
        }
        let fsType = withUnsafePointer(to: &sfs.f_fstypename) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MFSNAMELEN)) { cStr in
                String(cString: cStr)
            }
        }

        let decision = policyEngine.evaluateMount(
            process: process,
            mountFrom: mountFrom,
            mountPoint: mountPoint,
            fsType: fsType,
            disposition: disposition
        )

        let authResult: es_auth_result_t = decision.shouldAllowMount ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
        let response = es_respond_auth_result(client, message, authResult, false)
        let responseStatus = response == ES_RESPOND_RESULT_SUCCESS ? "success" : "failed_code_\(response.rawValue)"

        guard decision.isUSBMountCandidate else { return }

        let endNs = DispatchTime.now().uptimeNanoseconds
        let latencyMicros = max(1, UInt64((endNs - startNs) / 1_000))
        let remountExecutionEvent = ExecutionEvent(
            timestamp: nil,
            eventId: UUID().uuidString,
            module: "usb-storage-control",
            action: "remount",
            decision: decision.decisionString,
            ruleId: decision.matchingRuleId,
            policyVersion: decision.policyVersion,
            executablePath: process.executablePath,
            signingId: process.signingId,
            teamId: process.teamId,
            pid: process.pid,
            parentPid: process.parentPid,
            uid: process.uid,
            decisionLatencyMicros: latencyMicros,
            authResponseResult: responseStatus,
            resourcePath: "\(mountFrom) -> \(mountPoint) (\(fsType))"
        )
        logger.logEventAsync(remountExecutionEvent)
        if decision.decisionString == "blocked" {
            notifyBlockedIfHandlerPresent(remountExecutionEvent)
        }
    }

    private func handleUnmountMessage(
        message: UnsafePointer<es_message_t>
    ) {
        let msg = message.pointee
        let actor = msg.process.pointee
        let process = extractProcessContext(target: actor)
        let unmountEvent = msg.event.unmount
        var sfs = unmountEvent.statfs.pointee

        let mountFrom = withUnsafePointer(to: &sfs.f_mntfromname) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MNAMELEN)) { cStr in
                String(cString: cStr)
            }
        }
        let mountPoint = withUnsafePointer(to: &sfs.f_mntonname) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MNAMELEN)) { cStr in
                String(cString: cStr)
            }
        }

        guard mountPoint.hasPrefix("/Volumes/") else { return }

        logger.logEventAsync(
            ExecutionEvent(
                timestamp: nil,
                eventId: UUID().uuidString,
                module: "usb-storage-control",
                action: "unmount",
                decision: "allowed",
                ruleId: "usb-storage-unmount",
                policyVersion: policyEngine.currentPolicy().policyVersion,
                executablePath: process.executablePath,
                signingId: process.signingId,
                teamId: process.teamId,
                pid: process.pid,
                parentPid: process.parentPid,
                uid: process.uid,
                decisionLatencyMicros: 1,
                authResponseResult: "notify",
                resourcePath: "\(mountFrom) -> \(mountPoint)"
            )
        )
    }

    public func extractProcessContext(target: es_process_t) -> ProcessContext {
        let path = stringFromToken(target.executable.pointee.path) ?? ""
        let signingId = stringFromToken(target.signing_id)
        let teamId = stringFromToken(target.team_id)

        var cdhashCopy = target.cdhash
        let cdhashHex = withUnsafeBytes(of: &cdhashCopy) { (buf: UnsafeRawBufferPointer) -> String in
            buf.reduce(into: "") { $0 += String(format: "%02x", $1) }
        }

        let pid = pid_t(target.audit_token.val.5)
        let parentPid = pid_t(target.parent_audit_token.val.5) != 0 ? pid_t(target.parent_audit_token.val.5) : target.ppid
        let uid = uid_t(target.audit_token.val.1)

        return ProcessContext(
            pid: pid,
            parentPid: parentPid,
            uid: uid,
            signingId: signingId,
            teamId: teamId,
            isPlatformBinary: target.is_platform_binary,
            cdhash: cdhashHex,
            executablePath: path,
            codesigningFlags: target.codesigning_flags,
            isESClient: target.is_es_client
        )
    }

    private func stringFromToken(_ token: es_string_token_t) -> String? {
        guard token.length > 0, let data = token.data else { return nil }
        return String(decoding: UnsafeRawBufferPointer(start: data, count: token.length), as: UTF8.self)
    }

    private func writeHealthRecord(status: String, error: String?) {
        os_unfair_lock_lock(stateLock)
        self.lastError = error
        let record = HealthStatus(
            status: status,
            lastStarted: startTimeString,
            subscribedEvents: [
                "ES_EVENT_TYPE_AUTH_EXEC",
                "ES_EVENT_TYPE_AUTH_OPEN",
                "ES_EVENT_TYPE_AUTH_MOUNT",
                "ES_EVENT_TYPE_AUTH_REMOUNT",
                "ES_EVENT_TYPE_NOTIFY_UNMOUNT"
            ],
            lastError: error,
            totalAuthHandled: totalAuthHandled,
            totalDeadlineMisses: totalDeadlineMisses
        )
        os_unfair_lock_unlock(stateLock)

        let parentDir = (healthPath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: parentDir, withIntermediateDirectories: true)
        if let data = try? JSONEncoder().encode(record) {
            try? data.write(to: URL(fileURLWithPath: healthPath))
        }
    }
}
