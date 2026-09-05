import AppKit
import Foundation
import Security
import VeloxCore

struct InstalledApplication: Codable {
    let name: String
    let bundleIdentifier: String?
    let signingId: String?
    let teamId: String?
    let executablePath: String
    let bundlePath: String
    let iconDataURL: String?
    let protected: Bool
}

enum InstalledApplicationScanner {
    static func scan() -> [InstalledApplication] {
        let homeApplications = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications").path
        let roots = ["/Applications", "/System/Applications", homeApplications]
        var applicationsByPath: [String: InstalledApplication] = [:]

        for root in roots where FileManager.default.fileExists(atPath: root) {
            guard let enumerator = FileManager.default.enumerator(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.isDirectoryKey, .isApplicationKey],
                options: [.skipsHiddenFiles]
            ) else { continue }

            for case let url as URL in enumerator {
                guard url.pathExtension.caseInsensitiveCompare("app") == .orderedSame else { continue }
                enumerator.skipDescendants()
                guard let app = application(at: url) else { continue }
                applicationsByPath[app.executablePath] = app
            }
        }

        return applicationsByPath.values.sorted {
            $0.name.localizedStandardCompare($1.name) == .orderedAscending
        }
    }

    private static func application(at bundleURL: URL) -> InstalledApplication? {
        guard let bundle = Bundle(url: bundleURL),
              let executableURL = bundle.executableURL else { return nil }

        let identity = signingIdentity(for: bundleURL)
        let displayName = (bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
            ?? (bundle.object(forInfoDictionaryKey: "CFBundleName") as? String)
            ?? bundleURL.deletingPathExtension().lastPathComponent
        let bundleIdentifier = bundle.bundleIdentifier
        let signingId = identity.signingId ?? bundleIdentifier
        let isProtected = signingId.map {
            SecurityGuardian.selfSigningIdentifiers.contains($0) ||
                SecurityGuardian.criticalSigningIdentifiers.contains($0)
        } ?? false

        return InstalledApplication(
            name: displayName,
            bundleIdentifier: bundleIdentifier,
            signingId: signingId,
            teamId: identity.teamId,
            executablePath: executableURL.path,
            bundlePath: bundleURL.path,
            iconDataURL: iconDataURL(for: bundleURL.path),
            protected: isProtected
        )
    }

    private static func signingIdentity(for bundleURL: URL) -> (signingId: String?, teamId: String?) {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(bundleURL as CFURL, [], &code) == errSecSuccess,
              let code else { return (nil, nil) }

        var signingInformation: CFDictionary?
        guard SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &signingInformation
        ) == errSecSuccess,
              let values = signingInformation as? [String: Any] else { return (nil, nil) }

        return (
            values[kSecCodeInfoIdentifier as String] as? String,
            values[kSecCodeInfoTeamIdentifier as String] as? String
        )
    }

    private static func iconDataURL(for path: String) -> String? {
        let source = NSWorkspace.shared.icon(forFile: path)
        let target = NSImage(size: NSSize(width: 48, height: 48))
        target.lockFocus()
        NSGraphicsContext.current?.imageInterpolation = .high
        source.draw(
            in: NSRect(x: 0, y: 0, width: 48, height: 48),
            from: .zero,
            operation: .sourceOver,
            fraction: 1
        )
        target.unlockFocus()

        guard let tiff = target.tiffRepresentation,
              let bitmap = NSBitmapImageRep(data: tiff),
              let png = bitmap.representation(using: .png, properties: [:]) else { return nil }
        return "data:image/png;base64,\(png.base64EncodedString())"
    }
}
