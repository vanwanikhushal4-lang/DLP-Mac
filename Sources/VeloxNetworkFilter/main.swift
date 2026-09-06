import Foundation
import NetworkExtension
import VeloxCore
import os.log

let logger = Logger(subsystem: "co.velox.macdlp.networkfilter", category: "main")
logger.info("Velox Network Filter System Extension initializing...")

autoreleasepool {
    NEProvider.startSystemExtensionMode()
    NetworkEventService.shared.startListener()
}

dispatchMain()
