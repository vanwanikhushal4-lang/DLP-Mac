import Cocoa
import Foundation
import Darwin

let args = ProcessInfo.processInfo.arguments

if args.contains("--live-logs") {
    exit(VeloxLiveLogCommand.run(arguments: args))
}

if args.contains("--status") {
    // 1. Verify system extension registration directly via systemextensionsctl
    let pipe = Pipe()
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/bin/systemextensionsctl")
    proc.arguments = ["list"]
    proc.standardOutput = pipe
    try? proc.run()
    proc.waitUntilExit()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    let sysextOutput = String(data: data, encoding: .utf8) ?? ""

    let isRegistered = sysextOutput.contains("co.velox.macdlp.endpointsecurity")
    let isActivated = isRegistered && sysextOutput.contains("activated enabled")

    // 2. Read extension health record
    let healthPath = ProcessInfo.processInfo.environment["VELOX_HEALTH_PATH"] ?? "/Library/Application Support/VeloxMacDLP/health.json"
    struct HealthStatusRecord: Codable {
        let status: String
        let totalAuthHandled: UInt64
        let totalDeadlineMisses: UInt64
    }
    let healthData = try? Data(contentsOf: URL(fileURLWithPath: healthPath))
    let health = healthData.flatMap { try? JSONDecoder().decode(HealthStatusRecord.self, from: $0) }

    // 3. Formulate genuine status
    let msg: String
    if isActivated && health?.status == "enforcing" {
        msg = "ACTIVATION_STATUS: ENFORCING (System extension registered and actively enforcing AUTH_EXEC, handled \(health!.totalAuthHandled) auth events)\n"
    } else if isRegistered {
        msg = "ACTIVATION_STATUS: INSTALLED_UNHEALTHY (Registered in sysextd, but health record reports: \(health?.status ?? "no health record"))\n"
    } else {
        msg = "ACTIVATION_STATUS: NOT_INSTALLED (systemextensionsctl reports 0 extensions registered)\n"
    }

    write(STDOUT_FILENO, msg, msg.utf8.count)
    exit(0)
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
