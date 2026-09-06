import Foundation
import VeloxCore
import os.log

/// Sends privacy-safe network decisions directly to the root-owned event sink
/// in the Endpoint Security extension. The connection is asynchronous and never
/// participates in the allow/drop decision path.
final class NetworkEventForwarder: @unchecked Sendable {
    static let shared = NetworkEventForwarder()

    private let logger = Logger(subsystem: "co.velox.macdlp.networkfilter", category: "EventForwarder")
    private let lock = NSLock()
    private var connection: NSXPCConnection?
    private let encoder = JSONEncoder()

    private init() {
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    }

    func forward(_ event: ExecutionEvent) {
        guard let data = try? encoder.encode(event),
              data.count <= 32_768,
              let json = String(data: data, encoding: .utf8) else {
            logger.error("Unable to encode network-flow event.")
            return
        }

        let activeConnection = currentConnection()
        guard let sink = activeConnection.remoteObjectProxyWithErrorHandler({ [weak self, weak activeConnection] error in
            self?.logger.error("Network event forwarding failed: \(error.localizedDescription, privacy: .public)")
            self?.invalidate(activeConnection)
        }) as? VeloxNetworkEventSinkProtocol else {
            invalidate(activeConnection)
            return
        }

        sink.recordNetworkFlowEvent(json) { [weak self, weak activeConnection] response in
            guard Self.responseSucceeded(response) else {
                self?.logger.error("Endpoint Security event sink rejected a network-flow event.")
                self?.invalidate(activeConnection)
                return
            }
            self?.logger.info("Forwarded network-flow event to the protected activity log.")
        }
    }

    private func currentConnection() -> NSXPCConnection {
        lock.lock()
        defer { lock.unlock() }
        if let connection { return connection }

        let newConnection = NSXPCConnection(
            machServiceName: VeloxControlConstants.machServiceName,
            options: .privileged
        )
        newConnection.remoteObjectInterface = NSXPCInterface(with: VeloxNetworkEventSinkProtocol.self)
        newConnection.invalidationHandler = { [weak self, weak newConnection] in
            self?.invalidate(newConnection)
        }
        newConnection.interruptionHandler = { [weak self, weak newConnection] in
            self?.invalidate(newConnection)
        }
        newConnection.resume()
        connection = newConnection
        return newConnection
    }

    private func invalidate(_ staleConnection: NSXPCConnection?) {
        lock.lock()
        if staleConnection == nil || connection === staleConnection {
            connection = nil
        }
        lock.unlock()
        staleConnection?.invalidate()
    }

    private static func responseSucceeded(_ json: String) -> Bool {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return false
        }
        return object["ok"] as? Bool == true
    }
}
