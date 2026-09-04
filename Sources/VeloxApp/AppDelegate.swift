import Cocoa
import SystemExtensions
import os.log

public struct HostStatusRecord: Codable, Sendable {
    public let timestamp: String
    public let extensionIdentifier: String
    public let activationStatus: String // "completed", "approval_required", "reboot_required", "failed"
    public let details: String?
}

public final class AppDelegate: NSObject, NSApplicationDelegate, OSSystemExtensionRequestDelegate {
    public static let extensionIdentifier = "co.velox.macdlp.endpointsecurity"
    public static let statusFilePath = "/Library/Application Support/VeloxMacDLP/status.json"

    private let logger = Logger(subsystem: "co.velox.macdlp", category: "HostApp")

    public func applicationDidFinishLaunching(_ notification: Notification) {
        // Headless confirmation: Ensure dock tile is hidden
        NSApp.setActivationPolicy(.accessory)

        logger.info("Velox Mac DLP Headless Host starting...")

        let args = ProcessInfo.processInfo.arguments
        if args.contains("--deactivate") {
            deactivateSystemExtension()
        } else if args.contains("--status") {
            reportCurrentStatus()
            exit(0)
        } else {
            // Default action: activate extension
            activateSystemExtension()
        }
    }

    public func activateSystemExtension() {
        logger.info("Submitting activation request for \(Self.extensionIdentifier)...")
        print("ACTIVATION_REQUEST: Submitting activation request for \(Self.extensionIdentifier)...")
        fflush(stdout)

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    public func deactivateSystemExtension() {
        logger.info("Submitting deactivation request for \(Self.extensionIdentifier)...")
        print("ACTIVATION_REQUEST: Submitting deactivation request for \(Self.extensionIdentifier)...")
        fflush(stdout)

        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    private func recordStatus(status: String, details: String?) {
        let formatter = ISO8601DateFormatter()
        let record = HostStatusRecord(
            timestamp: formatter.string(from: Date()),
            extensionIdentifier: Self.extensionIdentifier,
            activationStatus: status,
            details: details
        )

        let dir = (Self.statusFilePath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        if let data = try? JSONEncoder().encode(record) {
            try? data.write(to: URL(fileURLWithPath: Self.statusFilePath))
        }
    }

    private func reportCurrentStatus() {
        if let data = try? Data(contentsOf: URL(fileURLWithPath: Self.statusFilePath)),
           let record = try? JSONDecoder().decode(HostStatusRecord.self, from: data) {
            print("Current Extension Status: \(record.activationStatus.uppercased()) (\(record.details ?? "No details"))")
        } else {
            print("Current Extension Status: NOT_RECORDED (Host app has not completed activation request)")
        }
    }

    // MARK: - OSSystemExtensionRequestDelegate

    public func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        logger.info("Replacing extension v\(existing.bundleShortVersion) with v\(ext.bundleShortVersion)")
        print("ACTIVATION_STATUS: REPLACING - Updating extension to version \(ext.bundleShortVersion)")
        return .replace
    }

    public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        let msg = "APPROVAL_REQUIRED - Administrator approval required in System Settings > Privacy & Security."
        logger.notice("\(msg)")
        print("ACTIVATION_STATUS: \(msg)")
        fflush(stdout)
        recordStatus(status: "approval_required", details: msg)
    }

    public func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            let msg = "COMPLETED - System extension activated and actively running."
            logger.info("\(msg)")
            print("ACTIVATION_STATUS: \(msg)")
            fflush(stdout)
            recordStatus(status: "completed", details: msg)
        case .willCompleteAfterReboot:
            let msg = "REBOOT_REQUIRED - System extension activation will complete after macOS reboot."
            logger.notice("\(msg)")
            print("ACTIVATION_STATUS: \(msg)")
            fflush(stdout)
            recordStatus(status: "reboot_required", details: msg)
        @unknown default:
            let msg = "UNKNOWN_RESULT - Result code \(result.rawValue)"
            logger.warning("\(msg)")
            print("ACTIVATION_STATUS: \(msg)")
            fflush(stdout)
            recordStatus(status: "unknown", details: msg)
        }
    }

    public func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let msg = "FAILED - \(error.localizedDescription)"
        logger.error("\(msg)")
        print("ACTIVATION_STATUS: \(msg)")
        fflush(stdout)
        recordStatus(status: "failed", details: error.localizedDescription)
    }
}
