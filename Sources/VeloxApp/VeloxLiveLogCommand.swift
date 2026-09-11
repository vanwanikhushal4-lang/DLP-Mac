import Foundation
import Darwin
import VeloxCore

/// Human-readable, read-only diagnostic console for operators and demos.
/// It follows the extension-owned JSONL audit log and never prints extracted
/// OCR text or document bytes.
enum VeloxLiveLogCommand {
    private static let defaultEventLogPath = "/Library/Logs/VeloxMacDLP/events.jsonl"
    private static let defaultHealthPath = "/Library/Application Support/VeloxMacDLP/health.json"
    private static let defaultPolicyPath = "/Library/Application Support/VeloxMacDLP/policy.json"

    private struct FileCursor {
        var inode: UInt64?
        var offset: UInt64 = 0
        var remainder = Data()
        var initialized = false
    }

    private struct HealthSnapshot: Decodable, Equatable {
        let status: String
        let totalAuthHandled: UInt64
        let totalDeadlineMisses: UInt64
    }

    private struct PolicySnapshot: Equatable {
        struct Rule: Equatable {
            let ruleId: String
            let name: String
            let type: String
            let classification: String
        }

        let version: Int
        let egressMode: String
        let channels: [String]
        let protectedClassifications: [String]
        let rules: [Rule]
    }

    private struct RuntimeSnapshot: Equatable {
        let endpointSecurity: String
        let networkFilter: String
    }

    static func run(arguments: [String]) -> Int32 {
        let includeHistory = arguments.contains("--history")
        let showAllEvents = arguments.contains("--all-events")
        let eventLogPath = environmentPath("VELOX_LOG_PATH", fallback: defaultEventLogPath)
        let healthPath = environmentPath("VELOX_HEALTH_PATH", fallback: defaultHealthPath)
        let policyPath = environmentPath("VELOX_POLICY_PATH", fallback: defaultPolicyPath)
        var cursor = FileCursor()
        var lastHealth: HealthSnapshot?
        var lastPolicy: PolicySnapshot?
        var lastRuntime: RuntimeSnapshot?
        var tick: UInt64 = 0

        setbuf(stdout, nil)
        print("\u{001B}[1;36mVeloxMacDLP Live Enforcement Console\u{001B}[0m")
        print("Read-only diagnostics · Ctrl-C to stop · OCR text is never displayed")
        print("Event source: \(eventLogPath)")
        print("────────────────────────────────────────────────────────────────────────")

        while true {
            autoreleasepool {
                if lastRuntime == nil || tick.isMultiple(of: 40) {
                    let runtime = readRuntimeSnapshot()
                    if runtime != lastRuntime {
                        printRuntime(runtime)
                        lastRuntime = runtime
                    }
                }

                let policy = readPolicySnapshot(at: policyPath)
                if policy != lastPolicy {
                    printPolicy(policy)
                    lastPolicy = policy
                }

                let health = readHealthSnapshot(at: healthPath)
                if health != lastHealth {
                    printHealthChange(health)
                    lastHealth = health
                }

                for event in readEvents(
                    at: eventLogPath,
                    cursor: &cursor,
                    includeHistory: includeHistory
                ) {
                    guard showAllEvents || isEnforcementRelevant(event) else { continue }
                    printEvent(event, policy: policy)
                }
            }
            tick &+= 1
            Thread.sleep(forTimeInterval: 0.25)
        }
    }

    private static func environmentPath(_ name: String, fallback: String) -> String {
        let value = ProcessInfo.processInfo.environment[name]?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return value.hasPrefix("/") ? value : fallback
    }

    private static func readEvents(
        at path: String,
        cursor: inout FileCursor,
        includeHistory: Bool
    ) -> [ExecutionEvent] {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
              let fileSize = (attributes[.size] as? NSNumber)?.uint64Value else {
            return []
        }
        let inode = (attributes[.systemFileNumber] as? NSNumber)?.uint64Value

        if !cursor.initialized {
            cursor.initialized = true
            cursor.inode = inode
            cursor.offset = includeHistory ? 0 : fileSize
            return []
        }
        if cursor.inode != inode || fileSize < cursor.offset {
            cursor.inode = inode
            cursor.offset = 0
            cursor.remainder.removeAll(keepingCapacity: true)
            print("\(timestamp())  \u{001B}[33mLOG ROTATED · attached to the new event file\u{001B}[0m")
        }
        guard fileSize > cursor.offset,
              let handle = FileHandle(forReadingAtPath: path) else { return [] }
        defer { try? handle.close() }

        do {
            try handle.seek(toOffset: cursor.offset)
            guard let newData = try handle.readToEnd(), !newData.isEmpty else { return [] }
            cursor.offset += UInt64(newData.count)
            cursor.remainder.append(newData)
        } catch {
            return []
        }

        guard let finalNewline = cursor.remainder.lastIndex(of: 0x0a) else { return [] }
        let completeData = cursor.remainder.prefix(through: finalNewline)
        let remainingStart = cursor.remainder.index(after: finalNewline)
        cursor.remainder = Data(cursor.remainder[remainingStart...])
        let lines = completeData.split(separator: 0x0a, omittingEmptySubsequences: true)
        let decoder = JSONDecoder()
        return lines.compactMap { try? decoder.decode(ExecutionEvent.self, from: Data($0)) }
    }

    private static func printEvent(_ event: ExecutionEvent, policy: PolicySnapshot?) {
        let time = displayTime(event.timestamp)
        let process = URL(fileURLWithPath: event.executablePath).lastPathComponent
        let path = event.resourcePath ?? "—"
        let route = routeDescription(event)
        let latency = formatLatency(event.decisionLatencyMicros)
        let response = event.authResponseResult ?? "n/a"

        if event.ruleId == "content-egress-classification-required" {
            section(time, event.decision == "blocked" ? "TRANSFER HELD" : "TRANSFER OBSERVED — AUDIT")
            detail(1, "ROUTE DETECTED", route)
            detail(2, "TRIGGER", triggerDescription(event))
            detail(3, "ACTOR", actorDescription(event, process: process))
            detail(4, "SOURCE", path)
            detail(5, "DESTINATION", destinationDescription(event))
            detail(
                6,
                "CLASSIFICATION CACHE",
                "MISS — no fresh result matched this exact path, size, modification time, and policy version"
            )
            detail(
                7,
                "POLICY REASON",
                "classified-egress is \(policy?.egressMode ?? "unknown"); unknown outbound content must be classified before release"
            )
            detail(
                8,
                "MACOS RESPONSE",
                event.decision == "blocked"
                    ? "DENY succeeded=\(response == "success") · decision returned in \(latency)"
                    : "AUDIT ONLY · request deferred to channel policy · \(latency)"
            )
            detail(9, "NEXT", "on-device OCR/content extraction queued; no document text is logged")
            return
        }

        if event.action == "egress-scan-failed" {
            section(time, "CLASSIFICATION FAILED", color: "\u{001B}[1;31m")
            detail(1, "FILE", path)
            detail(2, "FAILURE CODE", response)
            detail(3, "EXPLANATION", failureDescription(response))
            detail(
                4,
                "POLICY EFFECT",
                event.decision == "blocked"
                    ? "FAIL CLOSED — transfer remains denied because no trustworthy verdict exists"
                    : "AUDIT ONLY — failure recorded without a classification-layer denial"
            )
            detail(5, "REMEDIATION", failureRemediation(response))
            return
        }

        if event.module == "ocr-content-classification",
           event.interaction == "cached-for-egress" {
            let classes = event.classifications?.isEmpty == false
                ? event.classifications!.joined(separator: ", ")
                : "none"
            let engine = ocrMethod(event)
            let confidence = event.ocrConfidence.map { String(format: "%.0f%%", $0 * 100) } ?? "n/a"
            section(time, "ON-DEVICE CLASSIFICATION COMPLETE", color: "\u{001B}[1;35m")
            detail(1, "EXTRACTION METHOD", engine)
            detail(
                2,
                "ANALYSIS",
                "\(event.pageCount ?? 0) page/frame(s) · \(event.recognizedCharacterCount ?? 0) characters recognized · average confidence \(confidence) · \(latency)"
            )
            detail(3, "CONTENT HASH", event.contentHashPrefix ?? "—")
            detail(4, "DETECTED CATEGORIES", classes)
            detail(5, "MATCH REASON", classificationReason(event, policy: policy))
            detail(
                6,
                "CACHE",
                "ACCEPTED by the privileged extension and bound to current file metadata + policy v\(event.policyVersion)"
            )
            detail(
                7,
                "NEXT",
                classes == "none"
                    ? "retry may pass the content gate; other channel policies still apply"
                    : "retry will be denied on every enabled classified-egress route"
            )
            return
        }

        if event.action.hasPrefix("classified-content-") {
            let isPassed = event.action == "classified-content-passed"
            let classes = event.classifications?.isEmpty == false
                ? event.classifications!.joined(separator: ", ")
                : "none"
            section(
                time,
                isPassed ? "CONTENT GATE PASSED" : "TRANSFER BLOCKED",
                color: isPassed ? "\u{001B}[1;32m" : "\u{001B}[1;31m"
            )
            detail(1, "ROUTE DETECTED", route)
            detail(2, "TRIGGER", triggerDescription(event))
            detail(3, "ACTOR", actorDescription(event, process: process))
            detail(4, "SOURCE", path)
            detail(5, "DESTINATION", destinationDescription(event))
            detail(
                6,
                "CLASSIFICATION CACHE",
                "HIT · hash \(event.contentHashPrefix ?? "—") · categories \(classes)"
            )
            detail(
                7,
                "MATCH REASON",
                isPassed
                    ? "no configured protected classifier matched the file"
                    : classificationReason(event, policy: policy)
            )
            detail(
                8,
                "POLICY REASON",
                isPassed
                    ? "no detected category is protected by classified-egress policy v\(event.policyVersion)"
                    : "\(classes) is protected on \(route) by policy v\(event.policyVersion)"
            )
            detail(
                9,
                "MACOS RESPONSE",
                isPassed
                    ? "classification layer ALLOW · \(response); this records file-access authorization, not proof that the application completed transmission"
                    : "DENY succeeded=\(response == "success") · file access stopped in \(latency)"
            )
            return
        }

        let decisionColor: String
        switch event.decision {
        case "blocked": decisionColor = "\u{001B}[1;31m"
        case "would-block": decisionColor = "\u{001B}[1;33m"
        case "allowed": decisionColor = "\u{001B}[1;32m"
        default: decisionColor = "\u{001B}[0m"
        }
        section(time, "\(event.decision.uppercased()) · \(event.module)/\(event.action)", color: decisionColor)
        detail(1, "RESOURCE", path)
        detail(2, "DESTINATION", event.destinationPath ?? "not supplied by this event")
        detail(3, "ACTOR", actorDescription(event, process: process))
        detail(4, "RULE", event.ruleId ?? "no matching block rule")
        detail(5, "MACOS RESPONSE", "\(response) · \(latency)")
    }

    private static func section(_ time: String, _ title: String, color: String = "\u{001B}[1;36m") {
        print("")
        print("\(time)  \(color)━━ \(title) ━━\u{001B}[0m")
    }

    private static func detail(_ number: Int, _ label: String, _ value: String) {
        print("          \u{001B}[2m\(number). \(label)\u{001B}[0m  \(value)")
    }

    private static func actorDescription(_ event: ExecutionEvent, process: String) -> String {
        let signing = event.signingId ?? "unsigned/unknown signing ID"
        let team = event.teamId ?? "no team ID"
        return "\(process) · pid \(event.pid) · signing ID \(signing) · team \(team)"
    }

    private static func routeDescription(_ event: ExecutionEvent) -> String {
        let process = event.executablePath.lowercased()
        if let interaction = event.interaction, interaction.hasPrefix("usb:") {
            let volume = String(interaction.dropFirst(4))
            return "USB removable storage (volume: \(volume))"
        }
        switch event.module {
        case "web-upload-control":
            return "Web upload heuristic (browser read of a selected local file)"
        case "email-attachment-control":
            return "Native email attachment"
        case "nearby-transfer-control":
            if process.contains("bluetooth") {
                return "Bluetooth File Exchange"
            }
            if process.contains("sharingd") {
                return "AirDrop / Apple nearby sharing"
            }
            return "AirDrop / Bluetooth nearby transfer"
        case "usb-storage-control", "usb-encryption-control":
            return "USB removable storage"
        default:
            return event.interaction ?? event.module
        }
    }

    private static func destinationDescription(_ event: ExecutionEvent) -> String {
        if let destination = event.destinationPath, !destination.isEmpty {
            return destination
        }
        switch event.module {
        case "web-upload-control":
            return "website URL is not exposed by Endpoint Security AUTH_OPEN; browser extension telemetry is separate"
        case "email-attachment-control":
            return "recipient and Send action are not exposed by Endpoint Security; this is attachment file-read enforcement"
        case "nearby-transfer-control":
            return "recipient device is not exposed by Endpoint Security; Apple's sharing service read is authoritative"
        default:
            return "not supplied by this authorization event"
        }
    }

    private static func triggerDescription(_ event: ExecutionEvent) -> String {
        let flags = event.requestedOpenFlags.map { String(format: "0x%X", $0) } ?? "n/a"
        switch event.module {
        case "usb-storage-control":
            return "Endpoint Security AUTH_COPYFILE supplied an explicit source and external-volume destination"
        case "web-upload-control":
            return "Endpoint Security AUTH_OPEN observed a supported browser requesting read-only access (flags \(flags))"
        case "email-attachment-control":
            return "Endpoint Security AUTH_OPEN observed a configured mail client requesting read-only access (flags \(flags))"
        case "nearby-transfer-control":
            return "Endpoint Security AUTH_OPEN observed an Apple sharing/Bluetooth service reading the selected file (flags \(flags))"
        default:
            return "\(event.action) authorization event"
        }
    }

    private static func ocrMethod(_ event: ExecutionEvent) -> String {
        if event.authResponseResult == "vision-on-device" {
            return "Apple Vision OCR performed locally"
        }
        if event.fileType?.lowercased().contains("pdf") == true {
            return "embedded PDF text extraction performed locally"
        }
        return "plain-text extraction performed locally"
    }

    private static func classificationReason(_ event: ExecutionEvent, policy: PolicySnapshot?) -> String {
        guard let classifications = event.classifications, !classifications.isEmpty else {
            return "no configured sensitive-data rule matched the extracted content"
        }
        let matched = policy?.rules.filter { classifications.contains($0.classification) } ?? []
        if !matched.isEmpty {
            return matched.map {
                "\($0.name): \(ruleEvidence($0.type)) [\($0.ruleId)]"
            }.joined(separator: "; ")
        }
        return "matched configured rule \(event.ruleId ?? "unknown")"
    }

    private static func ruleEvidence(_ type: String) -> String {
        switch type {
        case "credit-card": return "a number passed payment-card format and Luhn checksum validation"
        case "indian-pan": return "text matched the validated Indian PAN structure"
        case "aadhaar": return "a 12-digit identity number passed Aadhaar format and Verhoeff checksum validation"
        case "keyword": return "one or more configured confidential-document markers matched"
        case "regex": return "the configured regular-expression rule matched"
        default: return "the configured \(type) classifier matched"
        }
    }

    private static func failureDescription(_ code: String) -> String {
        switch code {
        case "file-inaccessible": return "the logged-in Velox host could not read the regular file"
        case "unsupported-file-type": return "the file is not currently a supported image, PDF, or plain-text document"
        case "file-too-large": return "the file exceeded the configured classification size limit"
        case "pdf-page-limit-exceeded": return "the PDF exceeded the configured page limit"
        case "image-unreadable": return "ImageIO/Vision could not decode the image"
        case "pdf-unreadable": return "PDFKit could not open the PDF"
        case "no-recognizable-content": return "no usable embedded text or OCR-readable content was found"
        case "file-changed-during-scan": return "the file size or modification time changed while it was being analyzed"
        case "policy-unavailable": return "the host could not load and strictly validate the active policy"
        case "cache-sync-rejected": return "the privileged extension rejected the metadata-bound verdict"
        default: return "the on-device analysis returned an unexpected error"
        }
    }

    private static func failureRemediation(_ code: String) -> String {
        switch code {
        case "file-inaccessible": return "grant Velox Full Disk Access if the file is in a protected folder, then retry"
        case "unsupported-file-type": return "add a trusted extractor for this file type before enforcing it"
        case "file-too-large", "pdf-page-limit-exceeded": return "adjust the bounded OCR policy only after performance testing"
        case "file-changed-during-scan": return "wait until the file stops changing, then retry"
        case "cache-sync-rejected", "policy-unavailable": return "check extension health and policy validity"
        default: return "inspect the source file and retry; strict enforcement will continue holding it"
        }
    }

    private static func isEnforcementRelevant(_ event: ExecutionEvent) -> Bool {
        event.decision != "allowed" ||
            event.module == "ocr-content-classification" ||
            event.action.hasPrefix("classified-content-")
    }

    private static func readHealthSnapshot(at path: String) -> HealthSnapshot? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        return try? JSONDecoder().decode(HealthSnapshot.self, from: data)
    }

    private static func printHealthChange(_ health: HealthSnapshot?) {
        guard let health else {
            print("\(timestamp())  \u{001B}[31mHEALTH unavailable\u{001B}[0m")
            return
        }
        let color = health.status == "enforcing" ? "\u{001B}[1;32m" : "\u{001B}[1;31m"
        print(
            "\(timestamp())  \(color)HEALTH \(health.status.uppercased())\u{001B}[0m · " +
            "auth=\(health.totalAuthHandled) · deadline-misses=\(health.totalDeadlineMisses)"
        )
    }

    private static func readPolicySnapshot(at path: String) -> PolicySnapshot? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let version = root["policyVersion"] as? Int else { return nil }
        let ocr = root["ocrControl"] as? [String: Any]
        let rules = (ocr?["rules"] as? [[String: Any]] ?? []).compactMap { value -> PolicySnapshot.Rule? in
            guard let ruleId = value["ruleId"] as? String,
                  let name = value["name"] as? String,
                  let type = value["type"] as? String,
                  let classification = value["classification"] as? String else { return nil }
            return PolicySnapshot.Rule(
                ruleId: ruleId,
                name: name,
                type: type,
                classification: classification
            )
        }
        return PolicySnapshot(
            version: version,
            egressMode: ocr?["egressMode"] as? String ?? "disabled",
            channels: ocr?["protectedEgressChannels"] as? [String] ?? [],
            protectedClassifications: ocr?["protectedEgressClassifications"] as? [String] ?? [],
            rules: rules
        )
    }

    private static func printPolicy(_ policy: PolicySnapshot?) {
        guard let policy else {
            print("\(timestamp())  \u{001B}[31mPOLICY unavailable\u{001B}[0m")
            return
        }
        print(
            "\(timestamp())  POLICY v\(policy.version) · classified-egress=\(policy.egressMode) · " +
            "channels=\(policy.channels.joined(separator: ","))"
        )
        print(
            "              Protected categories: " +
            (policy.protectedClassifications.isEmpty
                ? policy.rules.map(\.classification).joined(separator: ", ")
                : policy.protectedClassifications.joined(separator: ", "))
        )
    }

    private static func readRuntimeSnapshot() -> RuntimeSnapshot {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/systemextensionsctl")
        process.arguments = ["list"]
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            return RuntimeSnapshot(
                endpointSecurity: activeVersion(
                    bundleID: "co.velox.macdlp.endpointsecurity",
                    output: output
                ),
                networkFilter: activeVersion(
                    bundleID: "co.velox.macdlp.networkfilter",
                    output: output
                )
            )
        } catch {
            return RuntimeSnapshot(endpointSecurity: "unavailable", networkFilter: "unavailable")
        }
    }

    private static func activeVersion(bundleID: String, output: String) -> String {
        for line in output.split(separator: "\n").map(String.init) where line.contains(bundleID) {
            guard line.contains("activated enabled") else { continue }
            if let open = line.range(of: "\(bundleID) ("),
               let close = line[open.upperBound...].firstIndex(of: ")") {
                return String(line[open.upperBound..<close])
            }
            return "activated"
        }
        return "not active"
    }

    private static func printRuntime(_ runtime: RuntimeSnapshot) {
        print(
            "\(timestamp())  ACTIVATION · endpoint-security=\(runtime.endpointSecurity) · " +
            "network-filter=\(runtime.networkFilter)"
        )
    }

    private static func displayTime(_ value: String) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = formatter.date(from: value) else { return value }
        return timestamp(date)
    }

    private static func timestamp(_ date: Date = Date()) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter.string(from: date)
    }

    private static func formatLatency(_ microseconds: UInt64) -> String {
        if microseconds >= 1_000_000 {
            return String(format: "%.2fs", Double(microseconds) / 1_000_000)
        }
        if microseconds >= 1_000 {
            return String(format: "%.2fms", Double(microseconds) / 1_000)
        }
        return "\(microseconds)µs"
    }
}
