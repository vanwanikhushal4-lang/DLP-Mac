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

    func setEmailAttachmentConfig(_ configJSON: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setEmailAttachmentConfig(configJSON, withReply: completion)
        }
    }

    func setUSBStorageMode(_ mode: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setUSBStorageMode(mode, withReply: completion)
        }
    }

    func setUSBEncryptionMode(_ mode: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setUSBEncryptionMode(mode, withReply: completion)
        }
    }

    func setNearbyTransferMode(_ mode: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setNearbyTransferMode(mode, withReply: completion)
        }
    }

    func setClipboardMode(_ mode: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setClipboardMode(mode, withReply: completion)
        }
    }

    func setPrinterMode(_ mode: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setPrinterMode(mode, withReply: completion)
        }
    }

    func setOCRMode(_ mode: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setOCRMode(mode, withReply: completion)
        }
    }

    func setScreenshotOCRMode(_ mode: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setScreenshotOCRMode(mode, withReply: completion)
        }
    }

    func setEndpointDiscoveryConfig(_ configJSON: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setEndpointDiscoveryConfig(configJSON, withReply: completion)
        }
    }

    func setCloudSyncMode(_ mode: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setCloudSyncMode(mode, withReply: completion)
        }
    }

    func setOpticalDiskImageMode(_ mode: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setOpticalDiskImageMode(mode, withReply: completion)
        }
    }

    func setOpticalDiskImageConfig(_ configJSON: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setOpticalDiskImageConfig(configJSON, withReply: completion)
        }
    }

    func setScreenWatermarkingMode(_ mode: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setScreenWatermarkingMode(mode, withReply: completion)
        }
    }

    func setPrintToPDFMode(_ mode: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setPrintToPDFMode(mode, withReply: completion)
        }
    }

    func setNetworkFlowMode(_ mode: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setNetworkFlowMode(mode, withReply: completion)
        }
    }

    func setNetworkFlowDefaultAction(_ action: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.setNetworkFlowDefaultAction(action, withReply: completion)
        }
    }

    func addNetworkFlowRule(_ ruleJSON: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.addNetworkFlowRule(ruleJSON, withReply: completion)
        }
    }

    func removeNetworkFlowRule(ruleId: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.removeNetworkFlowRule(ruleId: ruleId, withReply: completion)
        }
    }

    func setClipboardApplicationBlocked(
        signingId: String,
        executablePath: String,
        displayName: String,
        blocked: Bool,
        completion: @escaping (String) -> Void
    ) {
        withProxy(completion: completion) { proxy in
            proxy.setClipboardApplicationBlocked(
                signingId: signingId,
                executablePath: executablePath,
                displayName: displayName,
                blocked: blocked,
                withReply: completion
            )
        }
    }

    func recordClipboardEvent(_ payloadJSON: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.recordClipboardEvent(payloadJSON, withReply: completion)
        }
    }

    func recordBrowserUploadAttempt(_ payloadJSON: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.recordBrowserUploadAttempt(payloadJSON, withReply: completion)
        }
    }

    func recordOCRScanEvent(_ payloadJSON: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.recordOCRScanEvent(payloadJSON, withReply: completion)
        }
    }

    func recordEndpointDiscoveryEvent(_ payloadJSON: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.recordEndpointDiscoveryEvent(payloadJSON, withReply: completion)
        }
    }

    func syncEndpointDiscoveryClassifications(_ recordsJSON: String, completion: @escaping (String) -> Void) {
        withProxy(completion: completion) { proxy in
            proxy.syncEndpointDiscoveryClassifications(recordsJSON, withReply: completion)
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
        newConnection.exportedInterface = NSXPCInterface(with: VeloxClientProtocol.self)
        newConnection.exportedObject = VeloxNotificationManager.shared
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
