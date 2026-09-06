import Foundation

public struct PrinterQueueSnapshot: Codable, Sendable, Equatable {
    public let name: String
    public let isEnabled: Bool
    public let isAcceptingJobs: Bool

    public init(name: String, isEnabled: Bool, isAcceptingJobs: Bool) {
        self.name = name
        self.isEnabled = isEnabled
        self.isAcceptingJobs = isAcceptingJobs
    }
}

public struct PrinterJobSnapshot: Codable, Sendable, Equatable {
    public let identifier: String
    public let queueName: String

    public init(identifier: String, queueName: String) {
        self.identifier = identifier
        self.queueName = queueName
    }
}

/// Parses the stable, C-locale output produced by macOS `lpstat`.
/// Printer names cannot contain whitespace, slash, or `#`, which makes the
/// first-token and `printer <name>` forms safe to parse without a shell.
public enum PrinterQueueParser {
    public static func queues(
        printersOutput: String,
        acceptingOutput: String
    ) -> [PrinterQueueSnapshot] {
        var enabledByName: [String: Bool] = [:]
        var acceptingByName: [String: Bool] = [:]

        for rawLine in printersOutput.split(whereSeparator: \Character.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard line.hasPrefix("printer ") else { continue }
            let components = line.split(whereSeparator: \Character.isWhitespace)
            guard components.count >= 3 else { continue }
            let name = String(components[1])
            guard isSafeDestinationName(name) else { continue }
            enabledByName[name] = !line.lowercased().contains(" disabled ")
        }

        for rawLine in acceptingOutput.split(whereSeparator: \Character.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            let normalized = line.lowercased()
            guard normalized.contains(" accepting requests") ||
                    normalized.contains(" not accepting requests") else {
                continue
            }
            let components = line.split(whereSeparator: \Character.isWhitespace)
            guard let first = components.first else { continue }
            let name = String(first)
            guard isSafeDestinationName(name) else { continue }
            acceptingByName[name] = !normalized.contains(" not accepting requests")
        }

        let allNames = Set(enabledByName.keys).union(acceptingByName.keys)
        return allNames.sorted().map { name in
            PrinterQueueSnapshot(
                name: name,
                isEnabled: enabledByName[name] ?? false,
                isAcceptingJobs: acceptingByName[name] ?? false
            )
        }
    }

    public static func jobs(from output: String) -> [PrinterJobSnapshot] {
        output.split(whereSeparator: \Character.isNewline).compactMap { rawLine in
            let components = rawLine.split(whereSeparator: \Character.isWhitespace)
            guard let first = components.first else { return nil }
            let identifier = String(first)
            guard let separator = identifier.lastIndex(of: "-") else { return nil }
            let queueName = String(identifier[..<separator])
            let numericSuffix = identifier[identifier.index(after: separator)...]
            guard !numericSuffix.isEmpty,
                  numericSuffix.allSatisfy(\Character.isNumber),
                  isSafeDestinationName(queueName) else {
                return nil
            }
            return PrinterJobSnapshot(identifier: identifier, queueName: queueName)
        }
    }

    public static func isNoDestinationsMessage(_ output: String) -> Bool {
        output.localizedCaseInsensitiveContains("no destinations added")
    }

    private static func isSafeDestinationName(_ name: String) -> Bool {
        !name.isEmpty &&
            name.count <= 255 &&
            !name.contains(where: { $0.isWhitespace || $0 == "/" || $0 == "#" })
    }
}
