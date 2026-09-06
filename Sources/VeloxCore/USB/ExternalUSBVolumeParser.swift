import Foundation

public struct ExternalUSBVolumeDescriptor: Sendable, Equatable {
    public let deviceIdentifier: String
    public let volumeName: String
    public let mountPath: String
    public let sizeBytes: Int64

    public init(
        deviceIdentifier: String,
        volumeName: String,
        mountPath: String,
        sizeBytes: Int64
    ) {
        self.deviceIdentifier = deviceIdentifier
        self.volumeName = volumeName
        self.mountPath = mountPath
        self.sizeBytes = sizeBytes
    }
}

public enum ExternalUSBVolumeParser {
    public static func parseDiskutilListPlist(_ data: Data) throws -> [ExternalUSBVolumeDescriptor] {
        let value = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        var results: [ExternalUSBVolumeDescriptor] = []
        collect(value, into: &results)

        var uniqueByMountPath: [String: ExternalUSBVolumeDescriptor] = [:]
        for result in results {
            uniqueByMountPath[result.mountPath] = result
        }
        return uniqueByMountPath.values.sorted { $0.mountPath < $1.mountPath }
    }

    private static func collect(_ value: Any, into results: inout [ExternalUSBVolumeDescriptor]) {
        if let dictionary = value as? [String: Any] {
            if let descriptor = descriptor(from: dictionary) {
                results.append(descriptor)
            }
            for child in dictionary.values {
                collect(child, into: &results)
            }
        } else if let array = value as? [Any] {
            for child in array {
                collect(child, into: &results)
            }
        }
    }

    private static func descriptor(from dictionary: [String: Any]) -> ExternalUSBVolumeDescriptor? {
        guard let rawMountPath = dictionary["MountPoint"] as? String,
              let deviceIdentifier = dictionary["DeviceIdentifier"] as? String else {
            return nil
        }

        let mountPath = (rawMountPath as NSString).standardizingPath
        guard mountPath.hasPrefix("/Volumes/"), !deviceIdentifier.isEmpty else { return nil }

        let volumeName = (dictionary["VolumeName"] as? String)
            .flatMap { $0.isEmpty ? nil : $0 } ?? (mountPath as NSString).lastPathComponent
        let sizeBytes = (dictionary["Size"] as? NSNumber)?.int64Value ?? 0
        return ExternalUSBVolumeDescriptor(
            deviceIdentifier: deviceIdentifier,
            volumeName: volumeName,
            mountPath: mountPath,
            sizeBytes: sizeBytes
        )
    }
}
