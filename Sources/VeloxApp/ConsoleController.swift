import AppKit
import Foundation
@preconcurrency import SafariServices
import UniformTypeIdentifiers
import WebKit
import VeloxCore

@MainActor
final class ConsoleController: NSObject, WKScriptMessageHandler, WKNavigationDelegate, NSWindowDelegate {
    public static weak var current: ConsoleController?

    private let controlClient: ExtensionControlClient
    private let ocrService: OCRService
    private let endpointDiscoveryService: EndpointDiscoveryService
    private var schemeHandler: BundledWebSchemeHandler?
    private var window: NSWindow?
    private var webView: WKWebView?
    private var installedApplicationsCache: [InstalledApplication]?

    init(
        controlClient: ExtensionControlClient,
        ocrService: OCRService,
        endpointDiscoveryService: EndpointDiscoveryService
    ) {
        self.controlClient = controlClient
        self.ocrService = ocrService
        self.endpointDiscoveryService = endpointDiscoveryService
        super.init()
    }

    func broadcastLiveEvent(_ event: ExecutionEvent) {
        guard let data = try? JSONEncoder().encode(event),
              let json = String(data: data, encoding: .utf8),
              let webView else { return }
        webView.evaluateJavaScript(
            "window.veloxOnLiveEvent && window.veloxOnLiveEvent(\(json));"
        )
    }

    func show() {
        Self.current = self
        if let window {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let configuration = WKWebViewConfiguration()
        configuration.preferences.isElementFullscreenEnabled = false
        configuration.websiteDataStore = .nonPersistent()
        configuration.userContentController.add(self, name: "velox")
        guard let schemeHandler = BundledWebSchemeHandler() else { return }
        configuration.setURLSchemeHandler(schemeHandler, forURLScheme: "velox")
        self.schemeHandler = schemeHandler

        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = self
        webView.setValue(false, forKey: "drawsBackground")

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1180, height: 820),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "Velox Mac DLP"
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.minSize = NSSize(width: 980, height: 720)
        window.backgroundColor = NSColor(red: 9 / 255, green: 12 / 255, blue: 19 / 255, alpha: 1)
        window.contentView = webView
        window.delegate = self
        window.center()

        self.window = window
        self.webView = webView

        webView.load(URLRequest(url: URL(string: "velox://app/index.html")!))
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        return false
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.frameInfo.securityOrigin.protocol == "velox",
              let body = message.body as? [String: Any],
              let requestId = body["id"] as? String,
              let action = body["action"] as? String else { return }

        switch action {
        case "getSnapshot":
            controlClient.getSnapshot { [weak self] json in
                self?.deliverSnapshot(requestId: requestId, extensionJSON: json)
            }

        case "getEvents":
            let limit = body["limit"] as? Int ?? 30
            controlClient.getRecentEvents(limit: limit) { [weak self] json in self?.deliver(requestId: requestId, json: json) }

        case "setMode":
            guard let mode = body["mode"] as? String else {
                deliverError(requestId: requestId, message: "Missing policy mode.")
                return
            }
            controlClient.setMode(mode) { [weak self] json in self?.deliver(requestId: requestId, json: json) }

        case "setWebUploadMode":
            guard let mode = body["mode"] as? String else {
                deliverError(requestId: requestId, message: "Missing web-upload policy mode.")
                return
            }
            controlClient.setWebUploadMode(mode) { [weak self] json in
                self?.deliver(requestId: requestId, json: json)
            }

        case "setEmailAttachmentConfig":
            let configJSON: String
            if let string = body["config"] as? String {
                configJSON = string
            } else if let config = body["config"] as? [String: Any],
                      let data = try? JSONSerialization.data(withJSONObject: config),
                      let string = String(data: data, encoding: .utf8) {
                configJSON = string
            } else {
                deliverError(requestId: requestId, message: "Missing Email Attachment Control configuration.")
                return
            }
            controlClient.setEmailAttachmentConfig(configJSON) { [weak self] json in
                self?.deliverSnapshot(requestId: requestId, extensionJSON: json)
            }

        case "setUSBStorageMode":
            guard let mode = body["mode"] as? String else {
                deliverError(requestId: requestId, message: "Missing usb-storage policy mode.")
                return
            }
            controlClient.setUSBStorageMode(mode) { [weak self] json in
                self?.deliver(requestId: requestId, json: json)
            }

        case "setUSBEncryptionMode":
            guard let mode = body["mode"] as? String else {
                deliverError(requestId: requestId, message: "Missing USB encryption policy mode.")
                return
            }
            controlClient.setUSBEncryptionMode(mode) { [weak self] json in
                self?.deliver(requestId: requestId, json: json)
            }

        case "setNearbyTransferMode":
            guard let mode = body["mode"] as? String else {
                deliverError(requestId: requestId, message: "Missing nearby-transfer policy mode.")
                return
            }
            controlClient.setNearbyTransferMode(mode) { [weak self] json in
                self?.deliver(requestId: requestId, json: json)
            }

        case "setClipboardMode":
            guard let mode = body["mode"] as? String else {
                deliverError(requestId: requestId, message: "Missing clipboard-control mode.")
                return
            }
            controlClient.setClipboardMode(mode) { [weak self] json in
                self?.deliver(requestId: requestId, json: json)
            }

        case "setPrinterMode":
            guard let mode = body["mode"] as? String else {
                deliverError(requestId: requestId, message: "Missing printer-control mode.")
                return
            }
            controlClient.setPrinterMode(mode) { [weak self] json in
                self?.deliver(requestId: requestId, json: json)
            }

        case "setPrintToPDFMode":
            guard let mode = body["mode"] as? String else {
                deliverError(requestId: requestId, message: "Missing print-to-PDF mode.")
                return
            }
            controlClient.setPrintToPDFMode(mode) { [weak self] json in
                self?.deliver(requestId: requestId, json: json)
            }

        case "setOCRMode":
            guard let mode = body["mode"] as? String else {
                deliverError(requestId: requestId, message: "Missing OCR policy mode.")
                return
            }
            controlClient.setOCRMode(mode) { [weak self] json in
                self?.deliver(requestId: requestId, json: json)
            }

        case "setScreenshotOCRMode":
            guard let mode = body["mode"] as? String else {
                deliverError(requestId: requestId, message: "Missing screenshot OCR mode.")
                return
            }
            controlClient.setScreenshotOCRMode(mode) { [weak self] json in
                self?.deliver(requestId: requestId, json: json)
            }

        case "setEndpointDiscoveryConfig":
            let configJSON: String
            if let string = body["config"] as? String {
                configJSON = string
            } else if let config = body["config"] as? [String: Any],
                      let data = try? JSONSerialization.data(withJSONObject: config),
                      let string = String(data: data, encoding: .utf8) {
                configJSON = string
            } else {
                deliverError(requestId: requestId, message: "Missing Endpoint Data Discovery configuration.")
                return
            }
            controlClient.setEndpointDiscoveryConfig(configJSON) { [weak self] json in
                self?.deliverSnapshot(requestId: requestId, extensionJSON: json)
            }

        case "setOpticalDiskImageConfig":
            let configJSON: String
            if let string = body["config"] as? String {
                configJSON = string
            } else if let config = body["config"] as? [String: Any],
                      let data = try? JSONSerialization.data(withJSONObject: config),
                      let string = String(data: data, encoding: .utf8) {
                configJSON = string
            } else {
                deliverError(
                    requestId: requestId,
                    message: "Missing Optical & Disk Image Control configuration."
                )
                return
            }
            controlClient.setOpticalDiskImageConfig(configJSON) { [weak self] json in
                self?.deliverSnapshot(requestId: requestId, extensionJSON: json)
            }

        case "startEndpointDiscoveryScan":
            deliver(
                requestId: requestId,
                encodable: endpointDiscoveryService.startScan(trigger: "manual")
            )

        case "getEndpointDiscoveryStatus":
            deliver(requestId: requestId, encodable: endpointDiscoveryService.status())

        case "openFullDiskAccessSettings":
            if let url = URL(
                string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
            ) {
                NSWorkspace.shared.open(url)
            }
            deliver(
                requestId: requestId,
                encodable: ErrorResponse(ok: true, message: "Full Disk Access settings opened.")
            )

        case "scanOCRFile":
            chooseAndScanOCRFile(requestId: requestId)

        case "setNetworkFlowMode":
            guard let mode = body["mode"] as? String else {
                deliverError(requestId: requestId, message: "Missing network-flow policy mode.")
                return
            }
            controlClient.setNetworkFlowMode(mode) { [weak self] json in
                self?.deliver(requestId: requestId, json: json)
            }

        case "setNetworkFlowDefaultAction":
            guard let flowAction = body["defaultAction"] as? String ?? body["action"] as? String else {
                deliverError(requestId: requestId, message: "Missing network-flow default action.")
                return
            }
            controlClient.setNetworkFlowDefaultAction(flowAction) { [weak self] json in
                self?.deliver(requestId: requestId, json: json)
            }

        case "addNetworkFlowRule":
            let ruleJSON: String
            if let str = body["rule"] as? String {
                ruleJSON = str
            } else if let dict = body["rule"] as? [String: Any],
                      let data = try? JSONSerialization.data(withJSONObject: dict),
                      let str = String(data: data, encoding: .utf8) {
                ruleJSON = str
            } else {
                deliverError(requestId: requestId, message: "Missing or invalid network flow rule.")
                return
            }
            controlClient.addNetworkFlowRule(ruleJSON) { [weak self] json in
                self?.deliver(requestId: requestId, json: json)
            }

        case "removeNetworkFlowRule":
            guard let ruleId = body["ruleId"] as? String else {
                deliverError(requestId: requestId, message: "Missing ruleId to remove.")
                return
            }
            controlClient.removeNetworkFlowRule(ruleId: ruleId) { [weak self] json in
                self?.deliver(requestId: requestId, json: json)
            }

        case "setClipboardApplicationBlocked":
            guard let executablePath = body["executablePath"] as? String,
                  let displayName = body["displayName"] as? String,
                  let blocked = body["blocked"] as? Bool else {
                deliverError(requestId: requestId, message: "Invalid clipboard application request.")
                return
            }
            controlClient.setClipboardApplicationBlocked(
                signingId: body["signingId"] as? String ?? "",
                executablePath: executablePath,
                displayName: displayName,
                blocked: blocked
            ) { [weak self] json in
                self?.deliver(requestId: requestId, json: json)
            }

        case "openSafariExtensionSettings":
            SFSafariApplication.showPreferencesForExtension(
                withIdentifier: "co.velox.macdlp.uploadguard"
            ) { [weak self] error in
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    if error != nil {
                        if let safariURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Safari") {
                            let config = NSWorkspace.OpenConfiguration()
                            config.activates = true
                            NSWorkspace.shared.openApplication(at: safariURL, configuration: config, completionHandler: nil)
                        }
                    }
                    self.deliver(
                        requestId: requestId,
                        encodable: ErrorResponse(
                            ok: true,
                            message: error == nil
                                ? "Safari extension preferences opened."
                                : "Safari activated. If the extension is not yet listed, check Safari > Develop > Allow Unsigned Extensions, then enable Velox DLP Upload Guard in Settings > Extensions."
                        )
                    )
                }
            }
        case "setApplicationBlocked":
            guard let executablePath = body["executablePath"] as? String,
                  let displayName = body["displayName"] as? String,
                  let blocked = body["blocked"] as? Bool else {
                deliverError(requestId: requestId, message: "Invalid application-control request.")
                return
            }
            controlClient.setApplicationBlocked(
                signingId: body["signingId"] as? String ?? "",
                executablePath: executablePath,
                displayName: displayName,
                blocked: blocked
            ) { [weak self] json in
                self?.deliver(requestId: requestId, json: json)
            }

        case "listApplications":
            let refresh = body["refresh"] as? Bool ?? false
            if !refresh, let apps = installedApplicationsCache {
                deliver(
                    requestId: requestId,
                    encodable: ApplicationsResponse(ok: true, apps: apps, message: nil)
                )
                return
            }
            Task { @MainActor [weak self] in
                guard let self else { return }
                let apps = await InstalledApplicationScanner.scan()
                self.installedApplicationsCache = apps
                self.deliver(
                    requestId: requestId,
                    encodable: ApplicationsResponse(ok: true, apps: apps, message: nil)
                )
            }

        default:
            deliverError(requestId: requestId, message: "Unsupported native action '\(action)'.")
        }
    }

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping @MainActor @Sendable (WKNavigationActionPolicy) -> Void
    ) {
        if let scheme = navigationAction.request.url?.scheme, scheme != "velox", scheme != "about" {
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    nonisolated private func deliver(requestId: String, json: String) {
        Task { @MainActor [weak self] in
            guard let self, let webView = self.webView else { return }
            let requestLiteral = self.jsonStringLiteral(requestId)
            guard json.data(using: .utf8).flatMap({ try? JSONSerialization.jsonObject(with: $0) }) != nil else {
                self.deliverError(requestId: requestId, message: "The extension returned malformed data.")
                return
            }
            _ = try? await webView.evaluateJavaScript(
                "window.veloxNativeResponse(\(requestLiteral), \(json));"
            )
        }
    }

    /// Adds host-owned Network Extension activation state to the policy snapshot
    /// returned by the Endpoint Security XPC service. Keeping these states
    /// separate prevents the console from claiming that socket filtering is live
    /// merely because the Endpoint Security extension answered successfully.
    nonisolated private func deliverSnapshot(requestId: String, extensionJSON: String) {
        guard let data = extensionJSON.data(using: .utf8),
              var snapshot = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            deliver(requestId: requestId, json: extensionJSON)
            return
        }

        let record = HostExtensionStateStore.status(for: AppDelegate.networkExtensionIdentifier)
        let status = record?.activationStatus ?? "not_requested"
        snapshot["networkFilterStatus"] = status
        snapshot["networkFilterEnabled"] = status == "enabled"
        snapshot["networkFilterMessage"] = record?.details ?? "The Network Filter has not been activated yet."
        let discovery = endpointDiscoveryService.status()
        snapshot["endpointDiscoveryRunning"] = discovery.running
        snapshot["endpointDiscoveryCurrentScanId"] = discovery.currentScanId
        snapshot["endpointDiscoveryNextScheduledAt"] = discovery.nextScheduledAt
        snapshot["endpointDiscoveryReportDirectory"] = discovery.reportDirectory
        if let report = discovery.lastReport,
           let reportData = try? JSONEncoder().encode(report),
           let reportObject = try? JSONSerialization.jsonObject(with: reportData) {
            snapshot["endpointDiscoveryLastReport"] = reportObject
        }

        guard let enrichedData = try? JSONSerialization.data(
            withJSONObject: snapshot,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ), let enrichedJSON = String(data: enrichedData, encoding: .utf8) else {
            deliver(requestId: requestId, json: extensionJSON)
            return
        }
        deliver(requestId: requestId, json: enrichedJSON)
    }

    private func deliver<T: Encodable>(requestId: String, encodable: T) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(encodable),
              let json = String(data: data, encoding: .utf8) else {
            deliverError(requestId: requestId, message: "Native response encoding failed.")
            return
        }
        deliver(requestId: requestId, json: json)
    }

    private func deliverError(requestId: String, message: String) {
        deliver(
            requestId: requestId,
            encodable: ErrorResponse(ok: false, message: message)
        )
    }

    private func chooseAndScanOCRFile(requestId: String) {
        let panel = NSOpenPanel()
        panel.title = "Test Velox OCR Classification"
        panel.message = "Choose an image, PDF, or plain-text file. Extracted text stays in memory and is never returned to the console or activity log."
        panel.prompt = "Scan"
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.image, .pdf, .text]

        let completion: (NSApplication.ModalResponse) -> Void = { [weak self] response in
            guard let self else { return }
            guard response == .OK, let url = panel.url else {
                self.deliverError(requestId: requestId, message: "OCR scan cancelled.")
                return
            }
            guard let data = try? Data(
                contentsOf: URL(fileURLWithPath: PolicyManager.defaultPolicyPath),
                options: [.mappedIfSafe]
            ), let policy = try? VeloxPolicy.decodeStrict(from: data) else {
                self.deliverError(requestId: requestId, message: "The active OCR policy could not be loaded.")
                return
            }

            self.ocrService.analyze(
                url: url,
                config: policy.ocrControl,
                source: "manual"
            ) { [weak self] result in
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    switch result {
                    case .success(let report):
                        self.recordOCRReport(report)
                        self.deliver(requestId: requestId, encodable: report)
                    case .failure(let error):
                        self.deliverError(requestId: requestId, message: error.localizedDescription)
                    }
                }
            }
        }

        if let window {
            panel.beginSheetModal(for: window, completionHandler: completion)
        } else {
            completion(panel.runModal())
        }
    }

    private func recordOCRReport(_ report: OCRScanReport) {
        let payload: [String: Any] = [
            "source": report.source,
            "fileType": report.fileType,
            "contentHashPrefix": report.contentHashPrefix,
            "decision": report.decision,
            "ruleIds": report.matches.map(\.ruleId),
            "classifications": report.matches.map(\.classification),
            "recognizedCharacterCount": report.recognizedCharacterCount,
            "pageCount": report.pageCount,
            "averageConfidence": report.averageConfidence,
            "usedOCR": report.usedOCR,
            "cacheHit": report.cacheHit,
            "durationMillis": report.durationMillis,
            "remediation": "none"
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
              let json = String(data: data, encoding: .utf8) else { return }
        controlClient.recordOCRScanEvent(json) { _ in }
    }

    private func jsonStringLiteral(_ value: String) -> String {
        guard let data = try? JSONEncoder().encode(value) else { return "\"\"" }
        return String(decoding: data, as: UTF8.self)
    }

    private func loadErrorPage(_ message: String) {
        let escaped = message.replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;")
        webView?.loadHTMLString(
            "<body style='margin:0;background:#090c13;color:#fff;font:15px -apple-system;padding:40px'><h2>Velox Mac DLP</h2><p>\(escaped)</p></body>",
            baseURL: nil
        )
    }
}

private struct ApplicationsResponse: Codable {
    let ok: Bool
    let apps: [InstalledApplication]
    let message: String?
}

private struct ErrorResponse: Codable {
    let ok: Bool
    let message: String
}
