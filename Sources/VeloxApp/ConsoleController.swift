import AppKit
import Foundation
@preconcurrency import SafariServices
import WebKit

@MainActor
final class ConsoleController: NSObject, WKScriptMessageHandler, WKNavigationDelegate, NSWindowDelegate {
    private let controlClient = ExtensionControlClient()
    private var schemeHandler: BundledWebSchemeHandler?
    private var window: NSWindow?
    private var webView: WKWebView?

    func show() {
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
            controlClient.getSnapshot { [weak self] json in self?.deliver(requestId: requestId, json: json) }

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

        case "openSafariExtensionSettings":
            SFSafariApplication.showPreferencesForExtension(
                withIdentifier: "co.velox.macdlp.uploadguard"
            ) { [weak self] error in
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    self.deliver(
                        requestId: requestId,
                        encodable: ErrorResponse(
                            ok: error == nil,
                            message: error?.localizedDescription ?? "Safari extension settings opened."
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
            let apps = InstalledApplicationScanner.scan()
            let response = ApplicationsResponse(ok: true, apps: apps, message: nil)
            deliver(requestId: requestId, encodable: response)

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
