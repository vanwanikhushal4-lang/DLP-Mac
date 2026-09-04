import Foundation

public struct FileSecurityResult: Sendable {
    public let isRootOwned: Bool
    public let isProtectedFromNonRoot: Bool
    public let isSymlink: Bool
    public let posixPermissions: UInt16
    public let ownerUID: UInt32
    public let ownerGID: UInt32
    public let details: String
}

public enum FileSecurity {
    /// Validates whether a file and its parent directory are owned by root,
    /// protected from group/world writing, and NOT a symlink.
    public static func verifySecurity(atPath path: String) -> FileSecurityResult {
        var statBuf = stat()
        // Use lstat to prevent following symlinks
        if lstat(path, &statBuf) != 0 {
            return FileSecurityResult(
                isRootOwned: false,
                isProtectedFromNonRoot: false,
                isSymlink: false,
                posixPermissions: 0,
                ownerUID: 0,
                ownerGID: 0,
                details: "Path does not exist: \(path)"
            )
        }

        let isSymlink = (statBuf.st_mode & S_IFMT) == S_IFLNK
        if isSymlink {
            return FileSecurityResult(
                isRootOwned: false,
                isProtectedFromNonRoot: false,
                isSymlink: true,
                posixPermissions: UInt16(statBuf.st_mode & 0o7777),
                ownerUID: statBuf.st_uid,
                ownerGID: statBuf.st_gid,
                details: "SECURITY REJECTION: Path is a symlink: \(path)"
            )
        }

        // Check parent directory
        let parentPath = (path as NSString).deletingLastPathComponent
        var parentStatBuf = stat()
        if lstat(parentPath, &parentStatBuf) == 0 {
            if (parentStatBuf.st_mode & S_IFMT) == S_IFLNK {
                return FileSecurityResult(
                    isRootOwned: false,
                    isProtectedFromNonRoot: false,
                    isSymlink: true,
                    posixPermissions: UInt16(parentStatBuf.st_mode & 0o7777),
                    ownerUID: parentStatBuf.st_uid,
                    ownerGID: parentStatBuf.st_gid,
                    details: "SECURITY REJECTION: Parent directory is a symlink: \(parentPath)"
                )
            }
            if parentStatBuf.st_uid != 0 {
                return FileSecurityResult(
                    isRootOwned: false,
                    isProtectedFromNonRoot: false,
                    isSymlink: false,
                    posixPermissions: UInt16(parentStatBuf.st_mode & 0o7777),
                    ownerUID: parentStatBuf.st_uid,
                    ownerGID: parentStatBuf.st_gid,
                    details: "SECURITY REJECTION: Parent directory is not owned by root (UID \(parentStatBuf.st_uid)): \(parentPath)"
                )
            }
            if (parentStatBuf.st_mode & (S_IWGRP | S_IWOTH)) != 0 {
                return FileSecurityResult(
                    isRootOwned: false,
                    isProtectedFromNonRoot: false,
                    isSymlink: false,
                    posixPermissions: UInt16(parentStatBuf.st_mode & 0o7777),
                    ownerUID: parentStatBuf.st_uid,
                    ownerGID: parentStatBuf.st_gid,
                    details: "SECURITY REJECTION: Parent directory is group or world writable: \(parentPath)"
                )
            }
        }

        let isRoot = (statBuf.st_uid == 0)
        let mode = statBuf.st_mode
        let otherWrite = (mode & S_IWOTH) != 0
        let groupWrite = (mode & S_IWGRP) != 0
        // A file is ONLY protected if it is root-owned, not a symlink, and not group/world writable
        let isProtected = isRoot && !isSymlink && !otherWrite && !groupWrite

        var details = "UID: \(statBuf.st_uid), GID: \(statBuf.st_gid), Mode: \(String(format: "%o", mode))"
        if !isRoot {
            details += " [WARNING: Not owned by root (UID 0)]"
        }
        if otherWrite {
            details += " [REJECTED: Writable by world/others]"
        }
        if groupWrite {
            details += " [REJECTED: Writable by group]"
        }

        return FileSecurityResult(
            isRootOwned: isRoot,
            isProtectedFromNonRoot: isProtected,
            isSymlink: false,
            posixPermissions: UInt16(mode & 0o7777),
            ownerUID: statBuf.st_uid,
            ownerGID: statBuf.st_gid,
            details: details
        )
    }

    /// When running as root, secures the destination file and its parent directory.
    public static func secureFileIfNeeded(atPath path: String) {
        guard geteuid() == 0 else { return }

        let parent = (path as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: true, attributes: [
            .posixPermissions: 0o755,
            .ownerAccountID: 0,
            .groupOwnerAccountID: 0
        ])

        if FileManager.default.fileExists(atPath: path) {
            try? FileManager.default.setAttributes([
                .posixPermissions: 0o644,
                .ownerAccountID: 0,
                .groupOwnerAccountID: 0
            ], ofItemAtPath: path)
        }
    }
}
