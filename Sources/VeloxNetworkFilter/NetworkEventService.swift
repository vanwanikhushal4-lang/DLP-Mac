import Foundation
import Security
import VeloxCore
import os.log

/// Authenticated, metadata-only bridge from the Network Filter system extension
/// to the signed Velox host application.
final class NetworkEventService: NSObject, NSXPCListenerDelegate, VeloxNetworkEventServiceProtocol, @unchecked Sendable {
    static let shared = NetworkEventService()

    private let logger = Logger(subsystem: "co.velox.macdlp.networkfilter", category: "EventBridge")
    private let lock = NSLock()
    private var listener: NSXPCListener?
    private var clients: [NSXPCConnection] = []
    private let encoder = JSONEncoder()

    private override init() {
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        super.init()
    }

    func startListener() {
        lock.lock()
        defer { lock.unlock() }
        guard listener == nil else { return }

        let listener = NSXPCListener(machServiceName: VeloxNetworkEventConstants.machServiceName)
        listener.delegate = self
        listener.resume()
        self.listener = listener
        logger.info("Network event bridge started.")
    }

    func registerClient(withReply reply: @escaping (Bool) -> Void) {
        reply(true)
    }

    func broadcast(_ event: ExecutionEvent) {
        guard let data = try? encoder.encode(event),
              let json = String(data: data, encoding: .utf8) else {
            logger.error("Unable to encode a blocked network event.")
            return
        }

        lock.lock()
        let currentClients = clients
        lock.unlock()

        for connection in currentClients {
            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ [weak self, weak connection] error in
                self?.logger.error("Network event delivery failed: \(error.localizedDescription, privacy: .public)")
                if let connection { self?.remove(connection) }
            }) as? VeloxNetworkEventClientProtocol else {
                continue
            }
            proxy.handleNetworkEvent(json)
        }
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard isAuthorizedHost(connection) else { return false }

        connection.exportedInterface = NSXPCInterface(with: VeloxNetworkEventServiceProtocol.self)
        connection.exportedObject = self
        connection.remoteObjectInterface = NSXPCInterface(with: VeloxNetworkEventClientProtocol.self)
        connection.invalidationHandler = { [weak self, weak connection] in
            if let connection { self?.remove(connection) }
        }
        connection.interruptionHandler = { [weak self, weak connection] in
            if let connection { self?.remove(connection) }
        }

        lock.lock()
        clients.append(connection)
        lock.unlock()
        connection.resume()
        logger.info("Signed Velox host registered for network block events.")
        return true
    }

    private func remove(_ connection: NSXPCConnection) {
        lock.lock()
        clients.removeAll { $0 === connection }
        lock.unlock()
    }

    private func isAuthorizedHost(_ connection: NSXPCConnection) -> Bool {
        let attributes = [
            kSecGuestAttributePid: NSNumber(value: connection.processIdentifier)
        ] as CFDictionary

        var dynamicCode: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &dynamicCode) == errSecSuccess,
              let dynamicCode,
              SecCodeCheckValidity(dynamicCode, SecCSFlags(rawValue: kSecCSStrictValidate), nil) == errSecSuccess else {
            logger.error("Rejected network-event client PID \(connection.processIdentifier): invalid signature.")
            return false
        }

        var staticCode: SecStaticCode?
        var signingInformation: CFDictionary?
        guard SecCodeCopyStaticCode(dynamicCode, [], &staticCode) == errSecSuccess,
              let staticCode,
              SecCodeCopySigningInformation(
                staticCode,
                SecCSFlags(rawValue: kSecCSSigningInformation),
                &signingInformation
              ) == errSecSuccess,
              let values = signingInformation as? [String: Any] else {
            logger.error("Rejected network-event client PID \(connection.processIdentifier): missing identity.")
            return false
        }

        let identifier = values[kSecCodeInfoIdentifier as String] as? String
        let teamIdentifier = values[kSecCodeInfoTeamIdentifier as String] as? String
        let accepted = identifier == VeloxControlConstants.hostBundleIdentifier &&
            teamIdentifier == VeloxControlConstants.teamIdentifier

        if !accepted {
            logger.error(
                "Rejected network-event client PID \(connection.processIdentifier): identifier=\(identifier ?? "missing", privacy: .public), team=\(teamIdentifier ?? "missing", privacy: .public)"
            )
        }
        return accepted
    }
}
