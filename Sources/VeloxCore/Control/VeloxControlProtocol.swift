import Foundation

/// The only privileged control surface exposed by the Endpoint Security extension.
/// Values are JSON strings so the XPC contract remains Objective-C compatible and
/// can evolve without granting clients arbitrary file or process access.
@objc public protocol VeloxControlProtocol {
    func getSnapshot(withReply reply: @escaping (String) -> Void)

    func setMode(
        _ mode: String,
        withReply reply: @escaping (String) -> Void
    )

    func setWebUploadMode(
        _ mode: String,
        withReply reply: @escaping (String) -> Void
    )

    /// Records a browser-bound upload decision made before the website sees
    /// the selected files. The payload is JSON and is validated by the service.
    func recordBrowserUploadAttempt(
        _ payloadJSON: String,
        withReply reply: @escaping (String) -> Void
    )

    func setApplicationBlocked(
        signingId: String,
        executablePath: String,
        displayName: String,
        blocked: Bool,
        withReply reply: @escaping (String) -> Void
    )

    func getRecentEvents(
        limit: Int,
        withReply reply: @escaping (String) -> Void
    )
}

public enum VeloxControlConstants {
    public static let machServiceName = "L7US4BH7Q2.co.velox.macdlp.endpointsecurity.xpc"
    public static let hostBundleIdentifier = "co.velox.macdlp"
    public static let safariUploadGuardBundleIdentifier = "co.velox.macdlp.uploadguard"
    public static let authorizedControlBundleIdentifiers: Set<String> = [
        hostBundleIdentifier,
        safariUploadGuardBundleIdentifier
    ]
    public static let teamIdentifier = "L7US4BH7Q2"
}
