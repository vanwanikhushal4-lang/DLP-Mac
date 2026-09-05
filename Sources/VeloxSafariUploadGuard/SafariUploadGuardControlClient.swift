import Foundation

@objc private protocol SafariUploadGuardControlProtocol {
    func getSnapshot(withReply reply: @escaping (String) -> Void)
    func recordBrowserUploadAttempt(
        _ payloadJSON: String,
        withReply reply: @escaping (String) -> Void
    )
}

private enum SafariUploadGuardControlConstants {
    static let machServiceName = "L7US4BH7Q2.co.velox.macdlp.endpointsecurity.xpc"
}

final class SafariUploadGuardControlClient: @unchecked Sendable {
    private let lock = NSLock()
    private var connection: NSXPCConnection?

    func getSnapshot(completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.getSnapshot(withReply: completion)
        }
    }

    func recordUploadAttempt(_ payloadJSON: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.recordBrowserUploadAttempt(payloadJSON, withReply: completion)
        }
    }

    private func withProxy(
        completion: @escaping (String) -> Void,
        operation: (SafariUploadGuardControlProtocol) -> Void
    ) {
        let connection = currentConnection()
        let proxy = connection.remoteObjectProxyWithErrorHandler { [weak self] error in
            self?.invalidateConnection()
            completion(Self.errorJSON(error.localizedDescription))
        }
        guard let service = proxy as? SafariUploadGuardControlProtocol else {
            completion(Self.errorJSON("Velox policy service is unavailable."))
            return
        }
        operation(service)
    }

    private func currentConnection() -> NSXPCConnection {
        lock.lock()
        defer { lock.unlock() }
        if let connection { return connection }

        let connection = NSXPCConnection(
            machServiceName: SafariUploadGuardControlConstants.machServiceName,
            options: .privileged
        )
        connection.remoteObjectInterface = NSXPCInterface(with: SafariUploadGuardControlProtocol.self)
        connection.invalidationHandler = { [weak self] in self?.invalidateConnection() }
        connection.interruptionHandler = { [weak self] in self?.invalidateConnection() }
        connection.resume()
        self.connection = connection
        return connection
    }

    private func invalidateConnection() {
        lock.lock()
        let stale = connection
        connection = nil
        lock.unlock()
        stale?.invalidate()
    }

    private static func errorJSON(_ message: String) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: ["ok": false, "message": message]),
              let json = String(data: data, encoding: .utf8) else {
            return #"{"ok":false,"message":"Native bridge failure."}"#
        }
        return json
    }
}
