import Cocoa
import VeloxCore
import os.log

@MainActor
final class PasteboardMonitor {
    private let logger = Logger(subsystem: "co.velox.macdlp", category: "PasteboardMonitor")
    private let controlClient: ExtensionControlClient
    private var timer: Timer?
    private var lastChangeCount: Int = 0
    private var isMonitoring: Bool = false
    private var policyEngine: PolicyEngine
    private var lastBlockedTimestamp: Date = .distantPast

    init(controlClient: ExtensionControlClient) {
        self.controlClient = controlClient
        let policyPath = PolicyManager.defaultPolicyPath
        if let data = try? Data(contentsOf: URL(fileURLWithPath: policyPath)),
           let policy = try? VeloxPolicy.decodeStrict(from: data) {
            self.policyEngine = PolicyEngine(policy: policy)
        } else {
            self.policyEngine = PolicyEngine(policy: VeloxPolicy(
                policyVersion: 1,
                applicationControl: ApplicationControlConfig(mode: .auditOnly),
                webUploadControl: WebUploadControlConfig(mode: .enforce)
            ))
        }
        self.lastChangeCount = NSPasteboard.general.changeCount
    }

    public func start() {
        guard !isMonitoring else { return }
        isMonitoring = true
        lastChangeCount = NSPasteboard.general.changeCount

        // 1. Timer polling for pasteboard changes (500ms)
        timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.checkPasteboard()
            }
        }

        // 2. Immediate check when a new application is activated
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didActivateApplicationNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.checkPasteboard()
            }
        }

        logger.info("PasteboardMonitor started.")
    }

    public func stop() {
        timer?.invalidate()
        timer = nil
        isMonitoring = false
        NotificationCenter.default.removeObserver(self)
        logger.info("PasteboardMonitor stopped.")
    }

    public func reloadPolicy() {
        let policyPath = PolicyManager.defaultPolicyPath
        if let data = try? Data(contentsOf: URL(fileURLWithPath: policyPath)),
           let policy = try? VeloxPolicy.decodeStrict(from: data) {
            self.policyEngine.updatePolicy(policy)
        }
    }

    public func checkPasteboard() {
        let pasteboard = NSPasteboard.general
        let currentChangeCount = pasteboard.changeCount
        guard currentChangeCount != lastChangeCount else { return }

        // Only enforce when a browser is the frontmost application
        guard let frontmostApp = NSWorkspace.shared.frontmostApplication,
              let bundleId = frontmostApp.bundleIdentifier,
              PolicyEngine.isSupportedBrowserBundleId(bundleId) else {
            // Not a browser, don't interfere with normal workflow
            return
        }

        // Extract file paths from pasteboard
        var filePaths = Set<String>()

        // 1. Read NSURL objects
        if let urls = pasteboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL] {
            for url in urls where url.isFileURL {
                filePaths.insert(url.path)
            }
        }

        // 2. Read legacy filenames property list if any
        if let filenames = pasteboard.propertyList(forType: NSPasteboard.PasteboardType("NSFilenamesPboardType")) as? [String] {
            for path in filenames {
                filePaths.insert(path)
            }
        }

        guard !filePaths.isEmpty else {
            // No file paths in pasteboard
            lastChangeCount = currentChangeCount
            return
        }

        // Refresh policy in memory
        reloadPolicy()

        let decision = policyEngine.evaluateClipboardContent(filePaths: Array(filePaths))

        guard decision.shouldBlock || decision.decisionString == "would-block" else {
            lastChangeCount = currentChangeCount
            return
        }

        let blockedNames = decision.blockedPaths.map { ($0 as NSString).lastPathComponent }

        if decision.shouldBlock {
            // Enforce mode: Clear pasteboard to prevent paste into browser
            pasteboard.clearContents()
            pasteboard.setString(
                "[Blocked by Velox DLP: File upload from protected directory is prohibited]",
                forType: .string
            )
            // Update lastChangeCount to the new changeCount so our write doesn't re-trigger
            lastChangeCount = pasteboard.changeCount

            logger.warning("Blocked clipboard file transfer of \(blockedNames) to \(bundleId)")

            VeloxNotificationManager.shared.postBlockedNotification(
                module: "web-upload-control",
                action: "clipboard-paste",
                target: blockedNames.joined(separator: ", "),
                detail: bundleId
            )
        } else {
            // Audit-only mode: record event but don't clear
            lastChangeCount = currentChangeCount
            logger.info("Audited clipboard file transfer of \(blockedNames) to \(bundleId)")
        }

        // Debounce rapid duplicate events (within 1 second)
        let now = Date()
        guard now.timeIntervalSince(lastBlockedTimestamp) > 1.0 else { return }
        lastBlockedTimestamp = now

        // Report to system extension for persistent root logging
        let payload: [String: Any] = [
            "fileNames": blockedNames,
            "interaction": "paste",
            "pageURL": bundleId,
            "blocked": decision.shouldBlock
        ]
        if let jsonData = try? JSONSerialization.data(withJSONObject: payload),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            controlClient.recordBrowserUploadAttempt(jsonString) { _ in }
        }
    }
}
