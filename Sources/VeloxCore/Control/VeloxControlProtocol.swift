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

    func setEmailAttachmentConfig(
        _ configJSON: String,
        withReply reply: @escaping (String) -> Void
    )

    func setUSBStorageMode(
        _ mode: String,
        withReply reply: @escaping (String) -> Void
    )

    func setUSBEncryptionMode(
        _ mode: String,
        withReply reply: @escaping (String) -> Void
    )

    func setNearbyTransferMode(
        _ mode: String,
        withReply reply: @escaping (String) -> Void
    )

    func setClipboardMode(
        _ mode: String,
        withReply reply: @escaping (String) -> Void
    )

    func setPrinterMode(
        _ mode: String,
        withReply reply: @escaping (String) -> Void
    )

    func setOCRMode(
        _ mode: String,
        withReply reply: @escaping (String) -> Void
    )

    func setClassifiedEgressMode(
        _ mode: String,
        withReply reply: @escaping (String) -> Void
    )

    func setScreenshotOCRMode(
        _ mode: String,
        withReply reply: @escaping (String) -> Void
    )

    /// Replaces the complete Endpoint Data Discovery configuration after the
    /// extension validates and atomically persists the new policy version.
    func setEndpointDiscoveryConfig(
        _ configJSON: String,
        withReply reply: @escaping (String) -> Void
    )

    func setCloudSyncMode(
        _ mode: String,
        withReply reply: @escaping (String) -> Void
    )

    func setOpticalDiskImageMode(
        _ mode: String,
        withReply reply: @escaping (String) -> Void
    )

    func setOpticalDiskImageConfig(
        _ configJSON: String,
        withReply reply: @escaping (String) -> Void
    )

    func setScreenWatermarkingMode(
        _ mode: String,
        withReply reply: @escaping (String) -> Void
    )

    func setPrintToPDFMode(
        _ mode: String,
        withReply reply: @escaping (String) -> Void
    )

    func setNetworkFlowMode(
        _ mode: String,
        withReply reply: @escaping (String) -> Void
    )

    func setNetworkFlowDefaultAction(
        _ action: String,
        withReply reply: @escaping (String) -> Void
    )

    func addNetworkFlowRule(
        _ ruleJSON: String,
        withReply reply: @escaping (String) -> Void
    )

    func removeNetworkFlowRule(
        ruleId: String,
        withReply reply: @escaping (String) -> Void
    )

    func setClipboardApplicationBlocked(
        signingId: String,
        executablePath: String,
        displayName: String,
        blocked: Bool,
        withReply reply: @escaping (String) -> Void
    )

    /// Records a clipboard decision made by the logged-in host agent. Clipboard
    /// contents are never transmitted; only source identity and coarse data types.
    func recordClipboardEvent(
        _ payloadJSON: String,
        withReply reply: @escaping (String) -> Void
    )

    /// Records a browser-bound upload decision made before the website sees
    /// the selected files. The payload is JSON and is validated by the service.
    func recordBrowserUploadAttempt(
        _ payloadJSON: String,
        withReply reply: @escaping (String) -> Void
    )

    /// Records a privacy-safe OCR verdict. Extracted text and source file paths
    /// are forbidden from this payload.
    func recordOCRScanEvent(
        _ payloadJSON: String,
        withReply reply: @escaping (String) -> Void
    )

    /// Records a privacy-safe asynchronous egress-classification failure so
    /// operators can distinguish policy denial from unreadable/unsupported data.
    func recordEgressClassificationFailure(
        filePath: String,
        reasonCode: String,
        withReply reply: @escaping (String) -> Void
    )

    /// Records a content-free at-rest discovery finding or scan summary.
    func recordEndpointDiscoveryEvent(
        _ payloadJSON: String,
        withReply reply: @escaping (String) -> Void
    )

    /// Rehydrates the extension's metadata-bound, content-free classification
    /// cache after activation or restart. The extension validates every record.
    func syncEndpointDiscoveryClassifications(
        _ recordsJSON: String,
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

/// Client-side callback interface implemented by the host application (VeloxApp)
/// to receive real-time notifications of blocked events from the Endpoint Security extension.
@objc public protocol VeloxClientProtocol {
    func handleBlockedEvent(
        module: String,
        action: String,
        target: String,
        detail: String,
        timestamp: Double
    )

    /// Signals that Apple's signed screenshot tool created a candidate file.
    /// OCR runs asynchronously in the logged-in host after the ES response.
    func handlePotentialScreenshot(
        path: String,
        timestamp: Double
    )
}

/// Narrow, write-only event sink used by the signed Network Filter system
/// extension. It deliberately does not expose policy mutation methods.
@objc public protocol VeloxNetworkEventSinkProtocol {
    func recordNetworkFlowEvent(
        _ payloadJSON: String,
        withReply reply: @escaping (String) -> Void
    )
}

public enum VeloxControlConstants {
    public static let machServiceName = "L7US4BH7Q2.co.velox.macdlp.endpointsecurity.xpc"
    public static let hostBundleIdentifier = "co.velox.macdlp"
    public static let safariUploadGuardBundleIdentifier = "co.velox.macdlp.uploadguard"
    public static let networkFilterBundleIdentifier = "co.velox.macdlp.networkfilter"
    public static let authorizedControlBundleIdentifiers: Set<String> = [
        hostBundleIdentifier,
        safariUploadGuardBundleIdentifier
    ]
    public static let teamIdentifier = "L7US4BH7Q2"
}
