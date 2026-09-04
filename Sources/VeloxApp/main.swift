import Cocoa
import Foundation
import Darwin

let args = ProcessInfo.processInfo.arguments

if args.contains("--status") {
    let msg: String
    if let data = try? Data(contentsOf: URL(fileURLWithPath: AppDelegate.statusFilePath)),
       let record = try? JSONDecoder().decode(HostStatusRecord.self, from: data) {
        msg = "ACTIVATION_STATUS: \(record.activationStatus.uppercased()) - \(record.details ?? "No details")\n"
    } else {
        msg = "ACTIVATION_STATUS: NOT_INSTALLED (No active system extension registration found)\n"
    }
    write(STDOUT_FILENO, msg, msg.utf8.count)
    exit(0)
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
