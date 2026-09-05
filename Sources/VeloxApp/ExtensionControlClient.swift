import Foundation
import VeloxCore

final class ExtensionControlClient: @unchecked Sendable {
    private let lock = NSLock()
    private var connection: NSXPCConnection?

    func getSnapshot(completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.getSnapshot(withReply: completion)
        }
    }

    func setMode(_ mode: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setMode(mode, withReply: completion)
        }
    }

    func setWebUploadMode(_ mode: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setWebUploadMode(mode, withReply: completion)
        }
    }

    func setApplicationBlocked(
        signingId: String,
        executablePath: String,
        displayName: String,
        blocked: Bool,
        completion: @escaping (String) -> Void
    ) {
        withProxy(completion: completion) { proxy in
            proxy.setApplicationBlocked(
                signingId: signingId,
                executablePath: executablePath,
                displayName: displayName,
                blocked: blocked,
                withReply: completion
            )
        }
    }

    func getRecentEvents(limit: Int, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.getRecentEvents(limit: limit, withReply: completion)
        }
    }

    private func withProxy(
        completion: @escaping (String) -> Void,
        operation: (VeloxControlProtocol) -> Void
    ) {
        let connection = currentConnection()
        let proxy = connection.remoteObjectProxyWithErrorHandler { [weak self] error in
            self?.invalidateConnection()
            completion(Self.errorJSON("Unable to contact the Endpoint Security extension: \(error.localizedDescription)"))
        }

        guard let service = proxy as? VeloxControlProtocol else {
            completion(Self.errorJSON("The Endpoint Security control service is unavailable."))
            return
        }
        operation(service)
    }

    private func currentConnection() -> NSXPCConnection {
        lock.lock()
        defer { lock.unlock() }
        if let connection { return connection }

        let newConnection = NSXPCConnection(
            machServiceName: VeloxControlConstants.machServiceName,
            options: .privileged
        )
        newConnection.remoteObjectInterface = NSXPCInterface(with: VeloxControlProtocol.self)
        newConnection.invalidationHandler = { [weak self] in self?.invalidateConnection() }
        newConnection.interruptionHandler = { [weak self] in self?.invalidateConnection() }
        newConnection.resume()
        connection = newConnection
        return newConnection
    }

    private func invalidateConnection() {
        lock.lock()
        let staleConnection = connection
        connection = nil
        lock.unlock()
        staleConnection?.invalidate()
    }

    private static func errorJSON(_ message: String) -> String {
        let object: [String: Any] = ["ok": false, "message": message]
        guard let data = try? JSONSerialization.data(withJSONObject: object),
              let json = String(data: data, encoding: .utf8) else {
            return #"{"ok":false,"message":"Native bridge failure."}"#
        }
        return json
    }
}
