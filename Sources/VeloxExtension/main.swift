import Foundation
import VeloxCore
import EndpointSecurity
import os.log

let logger = Logger(subsystem: "co.velox.macdlp.endpointsecurity", category: "SystemExtension")
logger.info("Velox Mac DLP Endpoint Security Extension starting...")

let policyPath = ProcessInfo.processInfo.environment["VELOX_POLICY_PATH"] ?? PolicyManager.defaultPolicyPath
let logPath = ProcessInfo.processInfo.environment["VELOX_LOG_PATH"] ?? EventLogger.defaultLogPath

// Verify file security boundaries
if geteuid() == 0 {
    FileSecurity.secureFileIfNeeded(atPath: policyPath)
    FileSecurity.secureFileIfNeeded(atPath: logPath)
}

let eventLogger = EventLogger(logFilePath: logPath)
let policyManager = PolicyManager(policyPath: policyPath, logger: eventLogger)
let usbEncryptionAccessController = USBEncryptionAccessController()

let usbEncryptionCoordinator = USBEncryptionCoordinator(
    policyEngine: policyManager.policyEngine,
    eventLogger: eventLogger,
    accessController: usbEncryptionAccessController
)

let printerCoordinator = PrinterControlCoordinator(
    policyEngine: policyManager.policyEngine,
    eventLogger: eventLogger
)

let esService = EndpointSecurityService(
    policyEngine: policyManager.policyEngine,
    logger: eventLogger,
    usbEncryptionAccessController: usbEncryptionAccessController
)

let controlService = VeloxControlService(
    policyManager: policyManager,
    logPath: logPath,
    eventLogger: eventLogger,
    usbEncryptionCoordinator: usbEncryptionCoordinator,
    printerCoordinator: printerCoordinator
)

esService.onEventBlocked = { [weak controlService] event in
    controlService?.broadcastBlockedEvent(event)
}
printerCoordinator.onBlockedEvent = { [weak controlService] event in
    controlService?.broadcastBlockedEvent(event)
}
esService.onVolumeTopologyChanged = { [weak usbEncryptionCoordinator] in
    usbEncryptionCoordinator?.reconcileSoon()
}

let controlListenerDelegate = VeloxControlListenerDelegate(service: controlService)
let controlListener = NSXPCListener(machServiceName: VeloxControlConstants.machServiceName)
controlListener.delegate = controlListenerDelegate
controlListener.resume()

// When policy changes on disk, clear the ES kernel cache to prevent stale authorizations
policyManager.onPolicyReloaded = { newPolicy in
    logger.info("Policy reloaded to version \(newPolicy.policyVersion). Invalidating kernel cache.")
    esService.clearCache()
    usbEncryptionCoordinator.reconcileSoon()
    printerCoordinator.policyDidChange()
}

policyManager.onPolicyError = { errMessage in
    logger.error("Policy reload error: \(errMessage)")
}

policyManager.startMonitoring()
usbEncryptionCoordinator.start()
printerCoordinator.start()

// Trap termination signals for clean shutdown
let sigSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
sigSource.setEventHandler {
    logger.info("Received SIGTERM, shutting down Endpoint Security client...")
    policyManager.stopMonitoring()
    usbEncryptionCoordinator.stop()
    printerCoordinator.stop()
    esService.stop()
    eventLogger.flushSync()
    exit(0)
}
sigSource.resume()
signal(SIGTERM, SIG_IGN)

// Start Endpoint Security Client
let startResult = esService.start()
switch startResult {
    case .success:
        logger.info("Endpoint Security client connected and subscribed to ES_EVENT_TYPE_AUTH_EXEC.")
    case .failure(let error):
        logger.error("Failed to start Endpoint Security client: \(error). Exiting nonzero for supervised restart.")
        exit(1)
}

dispatchMain()
