import Foundation

/// Protects critical macOS operating system processes and Velox agent components
/// from being blocked by user or generic administrator rules.
///
/// Security Boundary Invariants:
/// 1. Apple critical processes MUST have isPlatformBinary == true AND an authentic Apple signing ID/path.
/// 2. Velox self processes MUST have Team ID L7US4BH7Q2, matching signing ID, and CS_VALID bit set.
/// 3. Never trust a signing identifier alone without cryptographic verification status.
public struct SecurityGuardian: Sendable {
    /// Kernel code-signing flag: signature is valid and untampered
    public static let CS_VALID: UInt32 = 0x00000001

    /// Expected Apple Developer Team Identifier for Velox Mac DLP
    public static let expectedVeloxTeamID = "L7US4BH7Q2"

    /// Critical macOS signing IDs that must NEVER be denied execution when isPlatformBinary == true
    public static let criticalSigningIdentifiers: Set<String> = [
        "com.apple.launchd",
        "com.apple.loginwindow",
        "com.apple.WindowServer",
        "com.apple.trustd",
        "com.apple.securityd",
        "com.apple.authd",
        "com.apple.opendirectoryd",
        "com.apple.syspolicyd",
        "com.apple.amfid",
        "com.apple.kernelmanagerd",
        "com.apple.tccd",
        "com.apple.diskarbitrationd",
        "com.apple.systemextensionsd",
        "com.apple.logd",
        "com.apple.notifyd",
        "com.apple.runningboardd"
    ]

    /// Critical system paths that are exempt ONLY when isPlatformBinary == true
    public static let criticalExecutablePaths: Set<String> = [
        "/sbin/launchd",
        "/usr/libexec/opendirectoryd",
        "/usr/libexec/trustd",
        "/usr/libexec/syspolicyd",
        "/usr/libexec/amfid",
        "/usr/libexec/kernelmanagerd"
    ]

    /// Velox Mac DLP signing IDs that are eligible for self-protection
    public static let selfSigningIdentifiers: Set<String> = [
        "co.velox.macdlp",
        "co.velox.macdlp.endpointsecurity"
    ]

    /// Returns true if the target process is cryptographically verified as an essential
    /// operating system component or an authentic Velox DLP agent binary.
    public static func isCriticalProcess(
        signingId: String?,
        teamId: String?,
        executablePath: String,
        isPlatformBinary: Bool,
        codesigningFlags: UInt32
    ) -> Bool {
        // 1. Velox Self-Protection Check:
        // Requires: Authentic Velox signing ID + matching Team ID + CS_VALID bit
        if let signingId = signingId, selfSigningIdentifiers.contains(signingId) {
            let hasValidSignature = (codesigningFlags & CS_VALID) != 0
            let hasExpectedTeam = (teamId == expectedVeloxTeamID)
            if hasValidSignature && hasExpectedTeam {
                return true
            }
            // If teamId or CS_VALID fails, DO NOT trust it as self process!
        }

        // 2. Apple Critical OS Component Check:
        // Requires: isPlatformBinary == true AND (critical signing ID OR critical system path)
        if isPlatformBinary {
            if let signingId = signingId, criticalSigningIdentifiers.contains(signingId) {
                return true
            }
            if criticalExecutablePaths.contains(executablePath) {
                return true
            }
            if executablePath == "/sbin/launchd" {
                return true
            }
        }

        return false
    }
}
