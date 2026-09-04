import Foundation

/// Encapsulates the security attributes and identifiers of a process intercepted during execution.
public struct ProcessContext: Sendable, Equatable {
    public let pid: pid_t
    public let parentPid: pid_t
    public let uid: uid_t
    public let signingId: String?
    public let teamId: String?
    public let isPlatformBinary: Bool
    public let cdhash: String?
    public let executablePath: String
    public let codesigningFlags: UInt32
    public let isESClient: Bool

    public init(
        pid: pid_t,
        parentPid: pid_t,
        uid: uid_t,
        signingId: String?,
        teamId: String?,
        isPlatformBinary: Bool,
        cdhash: String?,
        executablePath: String,
        codesigningFlags: UInt32 = 0,
        isESClient: Bool = false
    ) {
        self.pid = pid
        self.parentPid = parentPid
        self.uid = uid
        self.signingId = signingId
        self.teamId = teamId
        self.isPlatformBinary = isPlatformBinary
        self.cdhash = cdhash?.lowercased()
        self.executablePath = executablePath
        self.codesigningFlags = codesigningFlags
        self.isESClient = isESClient
    }
}
