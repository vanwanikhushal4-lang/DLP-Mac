import Foundation
import VeloxCore
import os.log

/// Registers the host with the Network Filter extension and forwards provider
/// events to the root-owned Velox activity log. If that logging service is
/// temporarily unavailable, the event is still shown locally.
final class VeloxNetworkEventClient: NSObject, VeloxNetworkEventClientProtocol, @unchecked Sendable {
    private let logger = Logger(subsystem: "co.velox.macdlp", category: "NetworkEventClient")
    private let queue = DispatchQueue(label: "co.velox.macdlp.network-event-client")
    private let controlClient = ExtensionControlClient()
    private var connection: NSXPCConnection?
    private var retryWorkItem: DispatchWorkItem?
    private var running = false

    func start() {
        queue.async { [weak self] in
            guard let self, !self.running else { return }
            self.running = true
            self.connect()
        }
    }

    func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            self.running = false
            self.retryWorkItem?.cancel()
            self.retryWorkItem = nil
            self.connection?.invalidate()
            self.connection = nil
        }
    }

    func handleNetworkEvent(_ eventJSON: String) {
        guard let data = eventJSON.data(using: .utf8), data.count <= 32_768,
              let event = try? JSONDecoder().decode(ExecutionEvent.self, from: data),
              event.module == "network-flow-control",
              event.action == "socket-connect",
              ["blocked", "would-block"].contains(event.decision) else {
            logger.error("Rejected malformed network event from provider.")
            return
        }

        controlClient.recordNetworkFlowEvent(eventJSON) { [weak self] response in
            guard let self else { return }
            guard Self.responseSucceeded(response) else {
                self.logger.error("Unable to persist provider event; presenting it directly.")
                self.present(event)
                return
            }
            self.logger.info("Forwarded network event into the Velox activity stream.")
        }
    }

    private func connect() {
        guard running, connection == nil else { return }

        let newConnection = NSXPCConnection(
            machServiceName: VeloxNetworkEventConstants.machServiceName,
            options: []
        )
        newConnection.remoteObjectInterface = NSXPCInterface(with: VeloxNetworkEventServiceProtocol.self)
        newConnection.exportedInterface = NSXPCInterface(with: VeloxNetworkEventClientProtocol.self)
        newConnection.exportedObject = self
        newConnection.invalidationHandler = { [weak self, weak newConnection] in
            self?.connectionEnded(newConnection)
        }
        newConnection.interruptionHandler = { [weak self, weak newConnection] in
            self?.connectionEnded(newConnection)
        }
        newConnection.resume()
        connection = newConnection

        guard let service = newConnection.remoteObjectProxyWithErrorHandler({ [weak self, weak newConnection] error in
            self?.logger.error("Network event registration failed: \(error.localizedDescription, privacy: .public)")
            self?.connectionEnded(newConnection)
        }) as? VeloxNetworkEventServiceProtocol else {
            connectionEnded(newConnection)
            return
        }

        service.registerClient { [weak self, weak newConnection] registered in
            guard let self else { return }
            if registered {
                self.logger.info("Registered for Network Filter block events.")
            } else {
                self.connectionEnded(newConnection)
            }
        }
    }

    private func connectionEnded(_ endedConnection: NSXPCConnection?) {
        let endedIdentifier = endedConnection.map(ObjectIdentifier.init)
        queue.async { [weak self] in
            guard let self else { return }
            guard let currentConnection = self.connection else {
                self.scheduleReconnect()
                return
            }
            if let endedIdentifier,
               ObjectIdentifier(currentConnection) != endedIdentifier {
                return
            }
            currentConnection.invalidate()
            self.connection = nil
            self.scheduleReconnect()
        }
    }

    private func scheduleReconnect() {
        guard running, retryWorkItem == nil else { return }
        let item = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.retryWorkItem = nil
            self.connect()
        }
        retryWorkItem = item
        queue.asyncAfter(deadline: .now() + 2, execute: item)
    }

    private func present(_ event: ExecutionEvent) {
        Task { @MainActor in
            ConsoleController.current?.broadcastLiveEvent(event)
        }
        guard event.decision == "blocked" else { return }
        VeloxNotificationManager.shared.postBlockedNotification(
            module: event.module,
            action: event.action,
            target: event.resourcePath ?? "remote destination",
            detail: event.executablePath
        )
    }

    private static func responseSucceeded(_ json: String) -> Bool {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return false
        }
        return object["ok"] as? Bool == true
    }
}
