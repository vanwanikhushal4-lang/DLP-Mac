import Foundation
import Network
import NetworkExtension
import Security
import VeloxCore
import os.log

open class FilterDataProvider: NEFilterDataProvider {
    private let logger = Logger(subsystem: "co.velox.macdlp.networkfilter", category: "FilterDataProvider")
    private let policyManager: PolicyManager
    private let eventLogger: EventLogger

    public init(policyManager: PolicyManager, eventLogger: EventLogger) {
        self.policyManager = policyManager
        self.eventLogger = eventLogger
        super.init()
    }

    override public init() {
        let policyPath = ProcessInfo.processInfo.environment["VELOX_POLICY_PATH"] ?? PolicyManager.defaultPolicyPath
        let logPath = ProcessInfo.processInfo.environment["VELOX_LOG_PATH"] ?? EventLogger.defaultLogPath
        let logger = EventLogger(logFilePath: logPath)
        self.eventLogger = logger
        self.policyManager = PolicyManager(policyPath: policyPath, logger: logger)
        super.init()
    }

    override open func startFilter(completionHandler: @escaping (Error?) -> Void) {
        logger.info("Velox Network Filter Data Provider starting...")
        policyManager.startMonitoring()
        completionHandler(nil)
    }

    override open func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("Velox Network Filter Data Provider stopping with reason: \(String(describing: reason))")
        policyManager.stopMonitoring()
        eventLogger.flushSync()
        completionHandler()
    }

    override open func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        let startTime = mach_absolute_time()

        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }

        // Only inspect outbound flows
        if flow.direction == .inbound {
            return .allow()
        }

        // Extract destination metadata
        var remoteHostname: String? = socketFlow.remoteHostname
        var remoteAddress: String? = nil
        var remotePort: Int = 0

        if #available(macOS 15.0, *) {
            if let ep = socketFlow.remoteFlowEndpoint {
                switch ep {
                case .hostPort(let host, let port):
                    remotePort = Int(port.rawValue)
                    let hostStr = "\(host)"
                    var sin = sockaddr_in()
                    var sin6 = sockaddr_in6()
                    let isV4 = inet_pton(AF_INET, hostStr, &sin.sin_addr) == 1
                    let isV6 = inet_pton(AF_INET6, hostStr, &sin6.sin6_addr) == 1

                    if isV4 || isV6 {
                        remoteAddress = hostStr
                    } else if remoteHostname == nil {
                        remoteHostname = hostStr
                    }
                default:
                    break
                }
            }
        } else {
            if let ep = (socketFlow as AnyObject).value(forKey: "remoteEndpoint") as? NSObject {
                if let host = ep.value(forKey: "hostname") as? String {
                    let portStr = ep.value(forKey: "port") as? String
                    remotePort = portStr.flatMap { Int($0) } ?? 0

                    var sin = sockaddr_in()
                    var sin6 = sockaddr_in6()
                    let isV4 = inet_pton(AF_INET, host, &sin.sin_addr) == 1
                    let isV6 = inet_pton(AF_INET6, host, &sin6.sin6_addr) == 1

                    if isV4 || isV6 {
                        remoteAddress = host
                    } else if remoteHostname == nil {
                        remoteHostname = host
                    }
                }
            }
        }

        let networkProtocol: NetworkProtocol
        switch socketFlow.socketProtocol {
        case IPPROTO_TCP:
            networkProtocol = .tcp
        case IPPROTO_UDP:
            networkProtocol = .udp
        default:
            networkProtocol = .any
        }

        // Resolve process context from audit token
        let processContext = resolveProcessContext(from: flow.sourceProcessAuditToken)

        let flowContext = NetworkFlowContext(
            process: processContext,
            remoteHostname: remoteHostname,
            remoteAddress: remoteAddress,
            remotePort: remotePort,
            networkProtocol: networkProtocol,
            isOutbound: true
        )

        let decision = policyManager.policyEngine.evaluateNetworkFlow(flowContext)

        let endTime = mach_absolute_time()
        var timebase = mach_timebase_info()
        mach_timebase_info(&timebase)
        let elapsedNanos = (endTime - startTime) * UInt64(timebase.numer) / UInt64(timebase.denom)
        let latencyMicros = elapsedNanos / 1000

        let destination = remoteHostname ?? remoteAddress ?? "unknown"
        let destDisplay = "\(destination):\(remotePort)"

        if decision.decisionString != "allowed" {
            let event = ExecutionEvent(
                module: "network-flow-control",
                action: "socket-connect",
                decision: decision.decisionString,
                ruleId: decision.matchingRuleId,
                policyVersion: decision.policyVersion,
                executablePath: processContext.executablePath,
                signingId: processContext.signingId,
                teamId: processContext.teamId,
                pid: processContext.pid,
                parentPid: processContext.parentPid,
                uid: processContext.uid,
                decisionLatencyMicros: latencyMicros,
                authResponseResult: decision.shouldAllowFlow ? "allowed" : "blocked",
                resourcePath: destination,
                pageURL: networkProtocol.rawValue,
                interaction: remotePort > 0 ? "\(networkProtocol.rawValue)/\(remotePort)" : networkProtocol.rawValue
            )
            eventLogger.logEventAsync(event)
            NetworkEventForwarder.shared.forward(event)
        }

        if !decision.shouldAllowFlow {
            logger.info("Dropping network flow from \(processContext.executablePath) to \(destDisplay) [Rule: \(decision.matchingRuleId ?? "none")]")
            return .drop()
        }

        return .allow()
    }

    private func resolveProcessContext(from auditTokenData: Data?) -> ProcessContext {
        guard let tokenData = auditTokenData, tokenData.count == MemoryLayout<audit_token_t>.size else {
            return ProcessContext(
                pid: 0,
                parentPid: 0,
                uid: 0,
                signingId: nil,
                teamId: nil,
                isPlatformBinary: false,
                cdhash: nil,
                executablePath: "unknown"
            )
        }

        var token = audit_token_t()
        (tokenData as NSData).getBytes(&token, length: MemoryLayout<audit_token_t>.size)

        let pid = pid_t(token.val.5)
        let uid = uid_t(token.val.1)

        var signingId: String? = nil
        var teamId: String? = nil
        var isPlatformBinary = false
        var cdhash: String? = nil
        var executablePath = "unknown"
        var csFlags: UInt32 = 0

        // SecCode copy guest
        let attributes: [CFString: Any] = [
            kSecGuestAttributeAudit: tokenData as CFData
        ]
        var secCode: SecCode?
        if SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, [], &secCode) == errSecSuccess,
           let code = secCode {
            var staticCode: SecStaticCode?
            if SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
               let sCode = staticCode {
                var infoCF: CFDictionary?
                if SecCodeCopySigningInformation(sCode, SecCSFlags(rawValue: kSecCSSigningInformation), &infoCF) == errSecSuccess,
                   let info = infoCF as? [String: Any] {
                    signingId = info[kSecCodeInfoIdentifier as String] as? String
                    teamId = info[kSecCodeInfoTeamIdentifier as String] as? String
                    if let flags = (info[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value {
                        csFlags = flags
                        let platformBinaryFlag: UInt32 = 0x0400_0000
                        isPlatformBinary = (flags & platformBinaryFlag) != 0
                    }
                    if let cdhashData = info[kSecCodeInfoUnique as String] as? Data {
                        cdhash = cdhashData.map { String(format: "%02x", $0) }.joined()
                    }
                }
            }
        }

        // Executable path fallback via proc_pidpath
        var pathBuffer = [CChar](repeating: 0, count: 4096)
        let pathLength = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
        if pathLength > 0 {
            let utf8Bytes = pathBuffer.prefix(Int(pathLength)).map { UInt8(bitPattern: $0) }
            executablePath = String(decoding: utf8Bytes, as: UTF8.self)
        }

        return ProcessContext(
            pid: pid,
            parentPid: 0,
            uid: uid,
            signingId: signingId,
            teamId: teamId,
            isPlatformBinary: isPlatformBinary,
            cdhash: cdhash,
            executablePath: executablePath,
            codesigningFlags: csFlags
        )
    }
}
