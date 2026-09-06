import Cocoa
@preconcurrency import SystemExtensions
@preconcurrency import SafariServices
@preconcurrency import NetworkExtension
import os.log

public struct HostStatusRecord: Codable, Sendable {
    public let timestamp: String
    public let extensionIdentifier: String
    public let activationStatus: String // "completed", "approval_required", "reboot_required", "failed"
    public let details: String?
}

/// System-extension requests are submitted by the logged-in host process, which
/// cannot reliably write into the root-owned shared support directory. Persist
/// activation state in the user's defaults so the bundled console can report
/// each extension independently instead of assuming that one successful request
/// means every protection provider is ready.
enum HostExtensionStateStore {
    private static let keyPrefix = "co.velox.macdlp.extension-status."

    static func record(
        identifier: String,
        status: String,
        details: String?
    ) {
        let record = HostStatusRecord(
            timestamp: ISO8601DateFormatter().string(from: Date()),
            extensionIdentifier: identifier,
            activationStatus: status,
            details: details
        )
        if let data = try? JSONEncoder().encode(record) {
            UserDefaults.standard.set(data, forKey: keyPrefix + identifier)
        }
    }

    static func status(for identifier: String) -> HostStatusRecord? {
        guard let data = UserDefaults.standard.data(forKey: keyPrefix + identifier) else {
            return nil
        }
        return try? JSONDecoder().decode(HostStatusRecord.self, from: data)
    }
}

public final class AppDelegate: NSObject, NSApplicationDelegate, OSSystemExtensionRequestDelegate, @unchecked Sendable {
    public static let extensionIdentifier = "co.velox.macdlp.endpointsecurity"
    public static let networkExtensionIdentifier = "co.velox.macdlp.networkfilter"

    private let logger = Logger(subsystem: "co.velox.macdlp", category: "HostApp")
    private var consoleController: ConsoleController?
    private var statusItem: NSStatusItem?
    private var pasteboardMonitor: PasteboardMonitor?
    private var activeEventMonitor: VeloxActiveEventMonitor?
    private var networkEventClient: VeloxNetworkEventClient?
    private enum ExtensionRequestOperation {
        case activation
        case deactivation
    }

    private struct ExtensionRequestContext {
        let identifier: String
        let operation: ExtensionRequestOperation
    }

    private var requestContexts: [ObjectIdentifier: ExtensionRequestContext] = [:]

    @MainActor
    public func applicationDidFinishLaunching(_ notification: Notification) {
        // Headless confirmation: Ensure dock tile is hidden
        NSApp.setActivationPolicy(.accessory)
        configureMenuBar()
        VeloxNotificationManager.shared.requestAuthorization()

        logger.info("Velox Mac DLP Headless Host starting...")

        let args = ProcessInfo.processInfo.arguments
        if args.contains("--deactivate") {
            deactivateSystemExtension()
        } else if args.contains("--status") {
            reportCurrentStatus()
            exit(0)
        } else {
            let consoleController = ConsoleController()
            self.consoleController = consoleController
            consoleController.show()

            let monitor = PasteboardMonitor(controlClient: ExtensionControlClient())
            self.pasteboardMonitor = monitor
            monitor.start()

            let activeMonitor = VeloxActiveEventMonitor()
            self.activeEventMonitor = activeMonitor
            activeMonitor.start()

            let networkEventClient = VeloxNetworkEventClient()
            self.networkEventClient = networkEventClient
            networkEventClient.start()

            if args.contains("--safari-settings") {
                openSafariExtensionSettings()
            }
            if !args.contains("--console-only") {
                activateSystemExtension()
            }
        }
    }

    @MainActor
    public func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    /// Finder/Launchpad reopens an existing LSUIElement process instead of
    /// launching it again. Always restore the hidden React console in that case.
    @MainActor
    public func applicationShouldHandleReopen(
        _ sender: NSApplication,
        hasVisibleWindows flag: Bool
    ) -> Bool {
        consoleController?.show()
        return true
    }

    @MainActor
    private func configureMenuBar() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.button?.image = NSImage(
            systemSymbolName: "shield.lefthalf.filled",
            accessibilityDescription: "Velox Mac DLP"
        )

        let menu = NSMenu()
        let openItem = NSMenuItem(title: "Open Velox Console", action: #selector(openConsole), keyEquivalent: "o")
        openItem.target = self
        menu.addItem(openItem)
        menu.addItem(.separator())
        let quitItem = NSMenuItem(title: "Quit Console", action: #selector(quitConsole), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)
        item.menu = menu
        statusItem = item
    }

    @MainActor @objc private func openConsole() {
        consoleController?.show()
    }

    @MainActor @objc private func openSafariExtensionSettings() {
        let logger = self.logger
        SFSafariApplication.showPreferencesForExtension(
            withIdentifier: "co.velox.macdlp.uploadguard"
        ) { error in
            if let error {
                logger.error("Unable to open Safari extension settings: \(error.localizedDescription, privacy: .public)")
                Task { @MainActor in
                    if let safariURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Safari") {
                        let config = NSWorkspace.OpenConfiguration()
                        config.activates = true
                        NSWorkspace.shared.openApplication(at: safariURL, configuration: config, completionHandler: nil)
                    }
                }
            }
        }
    }

    @MainActor @objc private func quitConsole() {
        NSApp.terminate(nil)
    }

    public func activateSystemExtension() {
        submitActivationRequest(for: Self.extensionIdentifier)
        submitActivationRequest(for: Self.networkExtensionIdentifier)
    }

    private func submitActivationRequest(for identifier: String) {
        logger.info("Submitting activation request for \(identifier, privacy: .public)...")
        print("ACTIVATION_REQUEST: Submitting activation request for \(identifier)...")
        fflush(stdout)

        HostExtensionStateStore.record(
            identifier: identifier,
            status: "activating",
            details: "Activation request submitted."
        )
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: identifier,
            queue: .main
        )
        request.delegate = self
        requestContexts[ObjectIdentifier(request)] = ExtensionRequestContext(
            identifier: identifier,
            operation: .activation
        )
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    public func deactivateSystemExtension() {
        submitDeactivationRequest(for: Self.extensionIdentifier)
        disableNetworkFilter { [weak self] in
            self?.submitDeactivationRequest(for: Self.networkExtensionIdentifier)
        }
    }

    private func submitDeactivationRequest(for identifier: String) {
        logger.info("Submitting deactivation request for \(identifier, privacy: .public)...")
        print("ACTIVATION_REQUEST: Submitting deactivation request for \(identifier)...")
        fflush(stdout)

        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: identifier,
            queue: .main
        )
        request.delegate = self
        requestContexts[ObjectIdentifier(request)] = ExtensionRequestContext(
            identifier: identifier,
            operation: .deactivation
        )
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    private func configureNetworkFilter() {
        HostExtensionStateStore.record(
            identifier: Self.networkExtensionIdentifier,
            status: "configuring",
            details: "The system extension is active; enabling its content-filter configuration."
        )
        let manager = NEFilterManager.shared()
        let operationLogger = logger
        manager.loadFromPreferences { error in
            if let error = error {
                operationLogger.error("Failed to load filter preferences: \(error.localizedDescription)")
                HostExtensionStateStore.record(
                    identifier: Self.networkExtensionIdentifier,
                    status: "failed",
                    details: "Unable to load Network Extension preferences: \(error.localizedDescription)"
                )
                return
            }

            let config = manager.providerConfiguration ?? NEFilterProviderConfiguration()
            config.filterDataProviderBundleIdentifier = Self.networkExtensionIdentifier
            config.filterSockets = true
            config.filterPackets = false
            manager.providerConfiguration = config
            manager.localizedDescription = "Velox Mac DLP Network Protection"
            manager.isEnabled = true
            manager.saveToPreferences { saveError in
                if let saveError = saveError {
                    operationLogger.error("Failed to save filter preferences: \(saveError.localizedDescription)")
                    HostExtensionStateStore.record(
                        identifier: Self.networkExtensionIdentifier,
                        status: "failed",
                        details: "Unable to enable the Network Extension filter: \(saveError.localizedDescription)"
                    )
                } else {
                    operationLogger.info("NEFilterManager successfully enabled.")
                    HostExtensionStateStore.record(
                        identifier: Self.networkExtensionIdentifier,
                        status: "enabled",
                        details: "Network content filter is installed and enabled."
                    )
                }
            }
        }
    }

    private func disableNetworkFilter(completion: @escaping @Sendable () -> Void) {
        let manager = NEFilterManager.shared()
        let operationLogger = logger
        manager.loadFromPreferences { _ in
            manager.isEnabled = false
            manager.saveToPreferences { error in
                if let error {
                    operationLogger.error("Failed to disable filter preferences: \(error.localizedDescription)")
                }
                HostExtensionStateStore.record(
                    identifier: Self.networkExtensionIdentifier,
                    status: "disabled",
                    details: error?.localizedDescription ?? "Network content filter disabled."
                )
                DispatchQueue.main.async(execute: completion)
            }
        }
    }

    private func recordStatus(identifier: String, status: String, details: String?) {
        HostExtensionStateStore.record(identifier: identifier, status: status, details: details)
    }

    private func reportCurrentStatus() {
        for identifier in [Self.extensionIdentifier, Self.networkExtensionIdentifier] {
            if let record = HostExtensionStateStore.status(for: identifier) {
                print("\(identifier): \(record.activationStatus.uppercased()) (\(record.details ?? "No details"))")
            } else {
                print("\(identifier): NOT_RECORDED (Host app has not completed an activation request)")
            }
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
        let identifier = context(for: request).identifier
        let msg = "APPROVAL_REQUIRED - Administrator approval required in System Settings > Privacy & Security."
        logger.notice("\(msg)")
        print("ACTIVATION_STATUS: \(msg)")
        fflush(stdout)
        recordStatus(identifier: identifier, status: "approval_required", details: msg)
    }

    public func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        let context = context(for: request)
        let identifier = context.identifier
        switch result {
        case .completed:
            let msg = context.operation == .activation
                ? "COMPLETED - System extension activated and actively running."
                : "COMPLETED - System extension deactivated."
            logger.info("\(msg)")
            print("ACTIVATION_STATUS: \(msg)")
            fflush(stdout)
            if context.operation == .deactivation {
                recordStatus(identifier: identifier, status: "disabled", details: msg)
            } else if identifier == Self.networkExtensionIdentifier {
                configureNetworkFilter()
            } else {
                recordStatus(identifier: identifier, status: "completed", details: msg)
            }
        case .willCompleteAfterReboot:
            let msg = "REBOOT_REQUIRED - System extension activation will complete after macOS reboot."
            logger.notice("\(msg)")
            print("ACTIVATION_STATUS: \(msg)")
            fflush(stdout)
            recordStatus(identifier: identifier, status: "reboot_required", details: msg)
        @unknown default:
            let msg = "UNKNOWN_RESULT - Result code \(result.rawValue)"
            logger.warning("\(msg)")
            print("ACTIVATION_STATUS: \(msg)")
            fflush(stdout)
            recordStatus(identifier: identifier, status: "unknown", details: msg)
        }
        requestContexts.removeValue(forKey: ObjectIdentifier(request))
    }

    public func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let identifier = context(for: request).identifier
        let msg = "FAILED - \(error.localizedDescription)"
        logger.error("\(msg)")
        print("ACTIVATION_STATUS: \(msg)")
        fflush(stdout)
        recordStatus(identifier: identifier, status: "failed", details: error.localizedDescription)
        requestContexts.removeValue(forKey: ObjectIdentifier(request))
    }

    private func context(for request: OSSystemExtensionRequest) -> ExtensionRequestContext {
        requestContexts[ObjectIdentifier(request)] ?? ExtensionRequestContext(
            identifier: Self.extensionIdentifier,
            operation: .activation
        )
    }
}
