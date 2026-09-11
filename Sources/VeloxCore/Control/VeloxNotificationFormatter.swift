import Foundation

public struct FormattedNotification: Equatable, Sendable {
    public let title: String
    public let subtitle: String
    public let body: String

    public init(title: String, subtitle: String, body: String) {
        self.title = title
        self.subtitle = subtitle
        self.body = body
    }
}

public enum VeloxNotificationFormatter {
    public static func format(
        module: String,
        action: String,
        target: String,
        detail: String
    ) -> FormattedNotification {
        let title = "Blocked by Velox DLP"

        switch module {
        case "application-control":
            let appName = parseApplicationName(from: target, detail: detail)
            let subtitle = "Application Blocked"
            let body = "'\(appName)' was blocked from launching by security policy."
            return FormattedNotification(title: title, subtitle: subtitle, body: body)

        case "web-upload-control":
            let subtitle = "Web Upload Blocked"
            let fileName = parseFileName(from: target)
            let browser = parseBrowserName(from: detail)

            let body: String
            if action == "clipboard-paste" {
                body = "Pasting protected file '\(fileName)' into \(browser) was blocked."
            } else {
                body = "Uploading '\(fileName)' to \(browser) was blocked by security policy."
            }
            return FormattedNotification(title: title, subtitle: subtitle, body: body)

        case "email-attachment-control":
            let subtitle = "Email Attachment Blocked"
            let fileName = parseFileName(from: target)
            let parts = detail.split(separator: "|", maxSplits: 1).map(String.init)
            let client = parts.first?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "Mail"
            let classification = parts.count > 1 && !parts[1].isEmpty
                ? parts[1]
                : "classified content"
            let body = "Attaching '\(fileName)' in \(client) was blocked because it contains \(classification)."
            return FormattedNotification(title: title, subtitle: subtitle, body: body)

        case "usb-storage-control":
            let subtitle = "USB Storage Blocked"
            let volumeName = parseVolumeName(from: target)
            let body = "External storage '\(volumeName)' was blocked from mounting."
            return FormattedNotification(title: title, subtitle: subtitle, body: body)

        case "usb-encryption-control":
            let subtitle = "USB Encryption Required"
            let volumeName = parseVolumeName(from: target)
            let body = "A plaintext copy to '\(volumeName)' was blocked. Copy into Velox Secure USB instead."
            return FormattedNotification(title: title, subtitle: subtitle, body: body)

        case "optical-disk-image-control":
            let volumeName = parseVolumeName(from: target)
            let isOpticalMedia = action.hasPrefix("optical-media")
            let subtitle = isOpticalMedia ? "Optical Media Blocked" : "Disk Image Blocked"
            let kind = isOpticalMedia ? "Optical media" : "Disk image"
            let body = "\(kind) '\(volumeName)' was blocked from mounting by security policy."
            return FormattedNotification(title: title, subtitle: subtitle, body: body)

        case "nearby-transfer-control":
            let fileName = parseFileName(from: target)
            let channel: String
            if action.hasPrefix("bluetooth") {
                channel = "Bluetooth file transfer"
            } else if action.hasPrefix("apple-sharing") {
                channel = "Apple nearby sharing"
            } else {
                channel = "AirDrop"
            }
            let subtitle = "Nearby Transfer Blocked"
            let body = "Sending '\(fileName)' through \(channel) was blocked by security policy."
            return FormattedNotification(title: title, subtitle: subtitle, body: body)

        case "clipboard-control":
            let subtitle = "Clipboard Copy Blocked"
            let application = detail.trimmingCharacters(in: .whitespacesAndNewlines)
            let source = application.isEmpty ? "this application" : application
            let content = target.trimmingCharacters(in: .whitespacesAndNewlines)
            let summary = content.isEmpty ? "clipboard data" : content
            let body = "Copying \(summary) from \(source) was blocked by security policy."
            return FormattedNotification(title: title, subtitle: subtitle, body: body)

        case "printer-control":
            let subtitle = "Printing Blocked"
            let queue = target.trimmingCharacters(in: .whitespacesAndNewlines)
            let destination = queue.isEmpty ? "this printer" : "printer '\(queue)'"
            let body = "Printing to \(destination) was blocked by security policy."
            return FormattedNotification(title: title, subtitle: subtitle, body: body)

        case "print-to-pdf-control":
            let subtitle = "PDF File Output Blocked"
            let fileName = parseFileName(from: target)
            let application = parseApplicationName(from: detail, detail: "")
            let body = "Creating '\(fileName)' from \(application) was blocked by security policy."
            return FormattedNotification(title: title, subtitle: subtitle, body: body)

        case "ocr-content-classification":
            let isScreenshot = action == "screenshot-scan"
            let subtitle = isScreenshot ? "Sensitive Screenshot Blocked" : "Sensitive Visual Content Blocked"
            let classifications = detail
                .split(separator: ",")
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
                .prefix(3)
                .joined(separator: ", ")
            let content = classifications.isEmpty ? "sensitive content" : classifications
            let body = isScreenshot
                ? "Velox DLP detected \(content) and secured the screenshot."
                : "Velox DLP detected \(content) in visual content."
            return FormattedNotification(title: title, subtitle: subtitle, body: body)

        case "network-flow-control":
            let subtitle = "Network Connection Blocked"
            let destination = target.trimmingCharacters(in: .whitespacesAndNewlines)
            let browserName = parseBrowserName(from: detail)
            let normalizedDetail = detail.lowercased()
            let appName: String
            if normalizedDetail.contains("mdnsresponder") {
                // DNS-filter events are attributed to the shared system resolver,
                // not to the originating browser. Do not mislabel that as the app.
                appName = ""
            } else if browserName != "browser" {
                appName = browserName
            } else {
                appName = parseApplicationName(from: detail, detail: "")
            }
            let blockedDestination = destination.isEmpty ? "a remote destination" : destination
            let body: String
            if appName.isEmpty || appName == "unknown" {
                body = "Velox DLP blocked \(blockedDestination)."
            } else {
                body = "Velox DLP blocked \(blockedDestination) for \(appName)."
            }
            return FormattedNotification(title: title, subtitle: subtitle, body: body)

        default:
            let subtitle = "Action Blocked"
            let body = "Action '\(action)' on '\(target)' was blocked by security policy."
            return FormattedNotification(title: title, subtitle: subtitle, body: body)
        }
    }

    public static func parseApplicationName(from path: String, detail: String) -> String {
        let nsPath = path as NSString
        let lastComponent = nsPath.lastPathComponent
        if lastComponent.contains(".app") {
            return (lastComponent as NSString).deletingPathExtension
        }
        if !lastComponent.isEmpty {
            return lastComponent
        }
        if !detail.isEmpty {
            return detail
        }
        return "Application"
    }

    public static func parseFileName(from pathOrNames: String) -> String {
        let trimmed = pathOrNames.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.contains(",") {
            let parts = trimmed.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            if let first = parts.first {
                let count = parts.count
                let name = (first as NSString).lastPathComponent
                return count > 1 ? "\(name) (and \(count - 1) other files)" : name
            }
        }
        let lastComponent = (trimmed as NSString).lastPathComponent
        return lastComponent.isEmpty ? "Protected File" : lastComponent
    }

    public static func parseBrowserName(from detail: String) -> String {
        let lower = detail.lowercased()
        if lower.contains("safari") || lower.contains("webkit.networking") { return "Safari" }
        if lower.contains("chrome") { return "Google Chrome" }
        if lower.contains("firefox") { return "Firefox" }
        if lower.contains("edge") { return "Microsoft Edge" }
        if lower.contains("brave") { return "Brave" }
        if lower.contains("arc") { return "Arc" }
        if lower.contains("opera") { return "Opera" }
        return "browser"
    }

    public static func parseVolumeName(from mountString: String) -> String {
        if mountString.contains("->") {
            let components = mountString.components(separatedBy: "->")
            if components.count > 1 {
                let right = components[1].trimmingCharacters(in: .whitespaces)
                let destination = right.components(separatedBy: " ").first ?? right
                let name = (destination as NSString).lastPathComponent
                if !name.isEmpty && name != "/" {
                    return name
                }
            }
        }
        let last = (mountString as NSString).lastPathComponent
        return (!last.isEmpty && last != "/") ? last : "Device"
    }
}

public final class VeloxNotificationDebouncer: @unchecked Sendable {
    private let lock = NSLock()
    private var timestamps: [String: Date] = [:]
    public let interval: TimeInterval

    public init(interval: TimeInterval = 3.0) {
        self.interval = interval
    }

    public func shouldDeliver(key: String, now: Date = Date()) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        if let last = timestamps[key], now.timeIntervalSince(last) < interval {
            return false
        }
        timestamps[key] = now
        if timestamps.count > 100 {
            timestamps = timestamps.filter { now.timeIntervalSince($0.value) < 60.0 }
        }
        return true
    }
}
