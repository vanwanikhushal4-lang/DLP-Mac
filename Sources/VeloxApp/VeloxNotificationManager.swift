import AppKit
import Foundation
import UserNotifications
import VeloxCore
import os.log

/// Manages desktop notifications ("Blocked by Velox DLP") for security events across
/// Application Control, Web Upload Control, USB Storage Control, nearby transfer,
/// Clipboard Control, physical printing, PDF file output, and disk-image or
/// optical-media mounting.
/// Delivers both a native AppKit floating HUD banner directly on screen and a macOS
/// Notification Center system banner via out-of-process dispatch.
public final class VeloxNotificationManager: NSObject, VeloxClientProtocol, UNUserNotificationCenterDelegate, @unchecked Sendable {
    public static let shared = VeloxNotificationManager()

    private let logger = Logger(subsystem: "co.velox.macdlp", category: "Notifications")
    private let debouncer = VeloxNotificationDebouncer(interval: 3.0)
    private let screenshotHandlerLock = NSLock()
    private var potentialScreenshotHandler: (@Sendable (String) -> Void)?
    private var isAuthorized = false

    override private init() {
        super.init()
    }

    /// Requests user authorization for alert banners and sounds, and sets delegate.
    public func requestAuthorization() {
        guard Bundle.main.bundleIdentifier != nil else {
            logger.info("Running unbundled, skipping UNUserNotificationCenter initialization.")
            return
        }
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound, .badge]) { [weak self] granted, error in
            if let error {
                self?.logger.info("UNUserNotificationCenter authorization status: \(error.localizedDescription, privacy: .public)")
                self?.isAuthorized = false
            } else if granted {
                self?.logger.info("UNUserNotificationCenter authorization granted.")
                self?.isAuthorized = true
            } else {
                self?.isAuthorized = false
            }
        }
    }

    // MARK: - UNUserNotificationCenterDelegate

    /// Ensures notification banners are presented even when the host application is active.
    public func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }

    // MARK: - VeloxClientProtocol

    /// XPC callback invoked when an action is blocked.
    public func handleBlockedEvent(
        module: String,
        action: String,
        target: String,
        detail: String,
        timestamp: Double
    ) {
        postBlockedNotification(
            module: module,
            action: action,
            target: target,
            detail: detail
        )
    }

    public func handlePotentialScreenshot(path: String, timestamp: Double) {
        screenshotHandlerLock.lock()
        let handler = potentialScreenshotHandler
        screenshotHandlerLock.unlock()
        handler?(path)
    }

    func setPotentialScreenshotHandler(_ handler: (@Sendable (String) -> Void)?) {
        screenshotHandlerLock.lock()
        potentialScreenshotHandler = handler
        screenshotHandlerLock.unlock()
    }

    // MARK: - Notification Dispatch & Presentation

    /// Dispatches a formatted native notification if not debounced.
    public func postBlockedNotification(
        module: String,
        action: String,
        target: String,
        detail: String
    ) {
        let debounceKey = "\(module):\(target)"
        guard debouncer.shouldDeliver(key: debounceKey) else {
            logger.debug("Debounced duplicate notification for key: \(debounceKey, privacy: .public)")
            return
        }

        let formatted = VeloxNotificationFormatter.format(
            module: module,
            action: action,
            target: target,
            detail: detail
        )

        // Deliver exactly one native macOS system notification
        if isAuthorized && Bundle.main.bundleIdentifier != nil {
            let content = UNMutableNotificationContent()
            content.title = formatted.title
            content.subtitle = formatted.subtitle
            content.body = formatted.body
            content.sound = .default

            let request = UNNotificationRequest(
                identifier: UUID().uuidString,
                content: content,
                trigger: nil
            )

            UNUserNotificationCenter.current().add(request) { [weak self] error in
                if let error {
                    self?.logger.debug("UNUserNotificationCenter failed: \(error.localizedDescription), using fallback")
                    self?.deliverSystemNotification(
                        title: formatted.title,
                        subtitle: formatted.subtitle,
                        body: formatted.body
                    )
                } else {
                    self?.logger.info("Posted UNUserNotification: \(formatted.subtitle) - \(formatted.body, privacy: .public)")
                }
            }
        } else {
            deliverSystemNotification(
                title: formatted.title,
                subtitle: formatted.subtitle,
                body: formatted.body
            )
        }
    }

    private func deliverSystemNotification(title: String, subtitle: String, body: String) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let escapedBody = body.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            let escapedTitle = title.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            let escapedSubtitle = subtitle.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            let script = "display notification \"\(escapedBody)\" with title \"\(escapedTitle)\" subtitle \"\(escapedSubtitle)\" sound name \"Basso\""

            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            process.arguments = ["-e", script]
            do {
                try process.run()
                process.waitUntilExit()
                self?.logger.info("Delivered macOS system notification: \(subtitle) - \(body, privacy: .public)")
            } catch {
                self?.logger.error("Failed to run osascript notification: \(error.localizedDescription, privacy: .public)")
            }
        }
    }
}
