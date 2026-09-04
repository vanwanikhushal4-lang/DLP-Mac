import XCTest
@testable import VeloxCore

final class SecurityGuardianTests: XCTestCase {

    func testAuthenticApplePlatformBinariesAreProtected() {
        let criticalSigningIds = [
            "com.apple.launchd",
            "com.apple.loginwindow",
            "com.apple.WindowServer",
            "com.apple.trustd",
            "com.apple.securityd",
            "com.apple.authd",
            "com.apple.opendirectoryd",
            "com.apple.syspolicyd",
            "com.apple.amfid",
            "com.apple.kernelmanagerd"
        ]

        for signingId in criticalSigningIds {
            XCTAssertTrue(
                SecurityGuardian.isCriticalProcess(
                    signingId: signingId,
                    teamId: nil,
                    executablePath: "/usr/libexec/\(signingId)",
                    isPlatformBinary: true,
                    codesigningFlags: SecurityGuardian.CS_VALID
                ),
                "\(signingId) must be recognized as critical when isPlatformBinary == true"
            )
        }
    }

    func testSpoofedApplePlatformBinaryIsNotProtected() {
        // Attacker signs malicious binary with ad-hoc identifier "com.apple.launchd"
        // but kernel reports isPlatformBinary == false
        let spoofedLaunchd = SecurityGuardian.isCriticalProcess(
            signingId: "com.apple.launchd",
            teamId: nil,
            executablePath: "/private/tmp/evil_launchd",
            isPlatformBinary: false, // NOT a platform binary!
            codesigningFlags: SecurityGuardian.CS_VALID
        )
        XCTAssertFalse(spoofedLaunchd, "Ad-hoc binary claiming com.apple.launchd with isPlatformBinary == false must NOT be trusted")

        let spoofedPath = SecurityGuardian.isCriticalProcess(
            signingId: nil,
            teamId: nil,
            executablePath: "/sbin/launchd",
            isPlatformBinary: false,
            codesigningFlags: 0
        )
        XCTAssertFalse(spoofedPath, "Path /sbin/launchd without platform binary status must NOT be trusted")
    }

    func testAuthenticVeloxSelfProtection() {
        // Authentic Velox binary: correct signingId + correct Team ID (L7US4BH7Q2) + CS_VALID
        let authenticHost = SecurityGuardian.isCriticalProcess(
            signingId: "co.velox.macdlp",
            teamId: "L7US4BH7Q2",
            executablePath: "/Applications/VeloxMacDLP.app/Contents/MacOS/VeloxMacDLP",
            isPlatformBinary: false,
            codesigningFlags: SecurityGuardian.CS_VALID
        )
        XCTAssertTrue(authenticHost, "Authentic Velox host must be protected")

        let authenticExtension = SecurityGuardian.isCriticalProcess(
            signingId: "co.velox.macdlp.endpointsecurity",
            teamId: "L7US4BH7Q2",
            executablePath: "/Applications/VeloxMacDLP.app/Contents/Library/SystemExtensions/co.velox.macdlp.endpointsecurity.systemextension/Contents/MacOS/co.velox.macdlp.endpointsecurity",
            isPlatformBinary: false,
            codesigningFlags: SecurityGuardian.CS_VALID
        )
        XCTAssertTrue(authenticExtension, "Authentic Velox extension must be protected")
    }

    func testSpoofedVeloxBinariesAreRejected() {
        // Attacker signs binary with signingId "co.velox.macdlp" but NO team ID (ad-hoc)
        let adHocSpoof = SecurityGuardian.isCriticalProcess(
            signingId: "co.velox.macdlp",
            teamId: nil,
            executablePath: "/tmp/fake_velox",
            isPlatformBinary: false,
            codesigningFlags: SecurityGuardian.CS_VALID
        )
        XCTAssertFalse(adHocSpoof, "Ad-hoc binary with no Team ID must NOT be trusted as Velox")

        // Attacker signs binary with a different Developer Team ID
        let wrongTeamSpoof = SecurityGuardian.isCriticalProcess(
            signingId: "co.velox.macdlp",
            teamId: "ROGUE12345",
            executablePath: "/tmp/fake_velox",
            isPlatformBinary: false,
            codesigningFlags: SecurityGuardian.CS_VALID
        )
        XCTAssertFalse(wrongTeamSpoof, "Binary with mismatched Team ID must NOT be trusted as Velox")

        // Attacker tampers with binary so CS_VALID bit is cleared (flag == 0)
        let tamperedVelox = SecurityGuardian.isCriticalProcess(
            signingId: "co.velox.macdlp",
            teamId: "L7US4BH7Q2",
            executablePath: "/tmp/fake_velox",
            isPlatformBinary: false,
            codesigningFlags: 0 // CS_VALID NOT set
        )
        XCTAssertFalse(tamperedVelox, "Binary with invalid code signature (no CS_VALID) must NOT be trusted as Velox")
    }
}
