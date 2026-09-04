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
                // Fail-safe guaranteed response: Never leave kernel waiting
                _ = es_respond_auth_result(esClient, messagePointer, ES_AUTH_RESULT_ALLOW, false)
            }
        }

        switch result {
        case ES_NEW_CLIENT_RESULT_SUCCESS:
            self.client = newClient
            self.isRunning = true
            let formatter = ISO8601DateFormatter()
            self.startTimeString = formatter.string(from: Date())

            // Subscribe to ES_EVENT_TYPE_AUTH_EXEC
            var events = [ES_EVENT_TYPE_AUTH_EXEC]
            let subResult = es_subscribe(newClient!, &events, 1)
            if subResult != ES_RETURN_SUCCESS {
                let err = "Failed to subscribe to ES_EVENT_TYPE_AUTH_EXEC: \(subResult.rawValue)"
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
        } else {
            // Guarantee: always respond to any other unhandled AUTH event with ALLOW
            let res = es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
            if res != ES_RESPOND_RESULT_SUCCESS {
                fputs("[VeloxEndpointSecurityService] es_respond_auth_result failed on fallback: \(res.rawValue)\n", stderr)
            }
        }
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
            subscribedEvents: ["ES_EVENT_TYPE_AUTH_EXEC"],
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
