import React, { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import shieldLogo from "./assets/velox-shield.png";
import "./styles.css";

function showFatalError(message) {
  const root = document.getElementById("root");
  if (!root || root.childElementCount > 0) return;
  root.innerHTML = `<div style="padding:40px;color:#ffb6bb;font:14px -apple-system"><h2>Velox console could not start</h2><p>${String(message).replace(/[<>&]/g, "")}</p></div>`;
}

window.addEventListener("error", event => showFatalError(event.message));
window.addEventListener("unhandledrejection", event => showFatalError(event.reason?.message || event.reason));

const pendingCalls = new Map();

window.veloxNativeResponse = (id, payload) => {
  const pending = pendingCalls.get(id);
  if (!pending) return;
  pendingCalls.delete(id);
  clearTimeout(pending.timeout);
  if (payload?.ok === false) pending.reject(new Error(payload.message || "Request failed"));
  else pending.resolve(payload);
};

function nativeCall(action, payload = {}) {
  return new Promise((resolve, reject) => {
    const handler = window.webkit?.messageHandlers?.velox;
    if (!handler) {
      reject(new Error("Open this console from the VeloxMacDLP application."));
      return;
    }

    const id = globalThis.crypto?.randomUUID?.()
      ?? `velox-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const timeoutMillis = action === "scanOCRFile"
      ? 120000
      : action === "listApplications"
        ? 30000
        : 8000;
    const timeout = setTimeout(() => {
      pendingCalls.delete(id);
      reject(new Error("The security extension did not respond."));
    }, timeoutMillis);
    pendingCalls.set(id, { resolve, reject, timeout });
    handler.postMessage({ id, action, ...payload });
  });
}

const modeCopy = {
  enforce: { label: "Enforce", detail: "Actively deny applications that match policy." },
  "audit-only": { label: "Audit only", detail: "Allow execution and record what would be blocked." },
  disabled: { label: "Disabled", detail: "Allow all application launches." },
};

const clipboardModeCopy = {
  "block-all": { label: "Block all", detail: "Remove every new clipboard item created on this Mac." },
  "block-selected-apps": { label: "Selected apps", detail: "Remove clipboard items only when they originate from selected applications." },
  disabled: { label: "Disabled", detail: "Do not monitor or clear normal clipboard copies." },
};

const networkFilterStatusCopy = {
  enabled: { label: "Filter enabled", detail: "The signed Network Extension is installed and enabled." },
  activating: { label: "Starting", detail: "macOS is processing the Network Extension activation request." },
  configuring: { label: "Configuring", detail: "The extension is active and its content-filter configuration is being enabled." },
  approval_required: { label: "Approval required", detail: "Approve Velox in System Settings → Privacy & Security, then reopen the app." },
  reboot_required: { label: "Restart required", detail: "Restart this Mac to finish activating the Network Extension." },
  failed: { label: "Filter unavailable", detail: "The Network Extension could not be activated or enabled." },
  disabled: { label: "Filter disabled", detail: "The macOS content-filter configuration is disabled." },
  not_requested: { label: "Not activated", detail: "The Network Extension has not been activated yet." },
  unknown: { label: "Status unknown", detail: "Velox has not received a current Network Extension status." },
};

function ShieldMark() {
  return (
    <div className="shield-mark" aria-hidden="true">
      <img src={shieldLogo} alt="" />
    </div>
  );
}

function StatusPill({ online }) {
  return <div className={`status-pill ${online ? "online" : "offline"}`}><span />{online ? "Agent online" : "Agent offline"}</div>;
}

function FeatureIcon({ name }) {
  const paths = {
    applications: <><rect x="3.5" y="3.5" width="7" height="7" rx="2" /><rect x="13.5" y="3.5" width="7" height="7" rx="2" /><rect x="3.5" y="13.5" width="7" height="7" rx="2" /><rect x="13.5" y="13.5" width="7" height="7" rx="2" /></>,
    "web-upload": <><path d="M12 16V4" /><path d="m7.5 8.5 4.5-4.5 4.5 4.5" /><path d="M5 13.5v4.25A2.25 2.25 0 0 0 7.25 20h9.5A2.25 2.25 0 0 0 19 17.75V13.5" /></>,
    email: <><rect x="3.5" y="5" width="17" height="14" rx="2.5" /><path d="m5 7 7 5.5L19 7" /><path d="M16.5 16.5 20 20" /><path d="M20 16.5 16.5 20" /></>,
    "usb-storage": <><path d="M12 3v13" /><path d="m8.5 6.5 3.5-3.5 3.5 3.5" /><path d="M12 11 7.5 15.5" /><circle cx="7" cy="16" r="1.5" /><path d="M12 13.5 16.5 18" /><rect x="15.2" y="17.2" width="2.6" height="2.6" rx=".5" /><path d="M12 16v4" /><circle cx="12" cy="20" r="1" /></>,
    "optical-media": <><circle cx="12" cy="12" r="8.5" /><circle cx="12" cy="12" r="2.2" /><path d="M12 3.5v3M20.5 12h-3M12 20.5v-3M3.5 12h3" /></>,
    "nearby-transfer": <><circle cx="12" cy="12" r="1.6" /><path d="M8.2 8.2a5.4 5.4 0 0 0 0 7.6M15.8 8.2a5.4 5.4 0 0 1 0 7.6" /><path d="M5.2 5.2a9.6 9.6 0 0 0 0 13.6M18.8 5.2a9.6 9.6 0 0 1 0 13.6" /></>,
    clipboard: <><rect x="5" y="5.5" width="14" height="15" rx="2.5" /><path d="M9 5.5V4.4A1.4 1.4 0 0 1 10.4 3h3.2A1.4 1.4 0 0 1 15 4.4v1.1" /><path d="M8.5 11h7M8.5 15h5" /></>,
    printer: <><path d="M7 9V4h10v5" /><rect x="4" y="9" width="16" height="8" rx="2.5" /><path d="M7 15h10v5H7z" /><circle cx="17" cy="12" r=".8" /></>,
    ocr: <><path d="M5 3.5H3.5V8M19 3.5h1.5V8M5 20.5H3.5V16M19 20.5h1.5V16" /><path d="M7 8.5h10M7 12h10M7 15.5h7" /></>,
    discovery: <><circle cx="11" cy="11" r="6.5" /><path d="m16 16 4.5 4.5" /><path d="M8 9h6M8 12h4" /></>,
    "network-flow": <><circle cx="6" cy="6" r="2.5" /><circle cx="18" cy="6" r="2.5" /><circle cx="12" cy="18" r="2.5" /><path d="M7.8 7.8 10.5 16" /><path d="M16.2 7.8 13.5 16" /><path d="M8.5 6h7" /></>,
  };
  return <svg viewBox="0 0 24 24" aria-hidden="true">{paths[name]}</svg>;
}

function OverviewFeatureCard({ icon, title, description, status, detail, tone, onOpen }) {
  return (
    <button className={`overview-feature-card ${tone}`} onClick={onOpen}>
      <span className="feature-card-glow" />
      <span className="feature-card-top">
        <span className="feature-icon"><FeatureIcon name={icon} /></span>
        <span className={`feature-status ${tone}`}><i />{status}</span>
      </span>
      <span className="feature-card-copy">
        <strong>{title}</strong>
        <span>{description}</span>
      </span>
      <span className="feature-card-footer"><span>{detail}</span><b>Open <i>›</i></b></span>
    </button>
  );
}

function AppRow({ app, blocked, busy, onToggle }) {
  return (
    <div className="app-row">
      <div className="app-identity">
        {app.iconDataURL ? <img src={app.iconDataURL} alt="" /> : <div className="fallback-icon">{app.name.slice(0, 1)}</div>}
        <div className="app-copy">
          <div className="app-title-line">
            <strong>{app.name}</strong>
            {app.protected && <span className="protected-tag">Protected</span>}
          </div>
          <span>{app.signingId || app.bundleIdentifier || app.executablePath}</span>
        </div>
      </div>
      <div className="app-action">
        <span className={blocked ? "blocked-label" : "allowed-label"}>{blocked ? "Blocked" : "Allowed"}</span>
        <button
          className={`switch ${blocked ? "checked" : ""}`}
          aria-label={`${blocked ? "Allow" : "Block"} ${app.name}`}
          aria-pressed={blocked}
          disabled={busy || app.protected}
          onClick={() => onToggle(app, !blocked)}
        ><span /></button>
      </div>
    </div>
  );
}

function ClipboardAppRow({ app, selected, busy, onToggle }) {
  return (
    <div className="app-row">
      <div className="app-identity">
        {app.iconDataURL ? <img src={app.iconDataURL} alt="" /> : <div className="fallback-icon">{app.name.slice(0, 1)}</div>}
        <div className="app-copy">
          <div className="app-title-line">
            <strong>{app.name}</strong>
            {app.protected && <span className="protected-tag">Velox protected</span>}
          </div>
          <span>{app.signingId || app.bundleIdentifier || app.executablePath}</span>
        </div>
      </div>
      <div className="app-action">
        <span className={selected ? "blocked-label" : "allowed-label"}>{selected ? "Selected" : "Allowed"}</span>
        <button
          className={`switch ${selected ? "checked" : ""}`}
          aria-label={`${selected ? "Allow clipboard copy from" : "Block clipboard copy from"} ${app.name}`}
          aria-pressed={selected}
          disabled={busy || app.protected}
          onClick={() => onToggle(app, !selected)}
        ><span /></button>
      </div>
    </div>
  );
}

function EventRow({ event }) {
  const isUploadEvent = event.module === "web-upload-control";
  const isEmailEvent = event.module === "email-attachment-control";
  const isClipboardEvent = event.module === "clipboard-control";
  const isUSBEvent = event.module === "usb-storage-control";
  const isUSBEncryptionEvent = event.module === "usb-encryption-control";
  const isOpticalEvent = event.module === "optical-disk-image-control";
  const isNearbyEvent = event.module === "nearby-transfer-control";
  const isPrinterEvent = event.module === "printer-control";
  const isPrintToPDFEvent = event.module === "print-to-pdf-control";
  const isOCREvent = event.module === "ocr-content-classification";
  const isDiscoveryEvent = event.module === "endpoint-data-discovery";
  const isNetworkFlowEvent = event.module === "network-flow-control";
  let appName = event.executablePath?.split("/").pop() || event.signingId || "Unknown";
  let detail = event.signingId || event.executablePath;

  if (isUploadEvent) {
    appName = event.resourcePath?.split("/").pop() || "Protected file";
    detail = `${event.signingId || "Browser"} · ${event.resourcePath || "Unknown file"}`;
  } else if (isEmailEvent) {
    appName = event.resourcePath?.split("/").pop() || "Classified attachment";
    detail = `${event.interaction || event.signingId || "Native mail client"} · ${event.classifications?.join(", ") || "Classified content"}`;
  } else if (isClipboardEvent) {
    appName = event.pageURL || event.signingId || "Application";
    detail = `${event.resourcePath || "clipboard data"} · ${event.signingId || event.executablePath || "unknown source"}`;
  } else if (isUSBEvent) {
    appName = event.action === "mount" ? "USB Storage Mount" : (event.action === "remount" ? "USB Remount" : "USB Disconnect");
    detail = `${event.resourcePath || "External Drive"}`;
  } else if (isUSBEncryptionEvent) {
    if (event.action === "container-created") appName = "Encrypted container created";
    else if (event.action === "container-mounted") appName = "Velox Secure USB mounted";
    else if (event.action === "container-required") appName = "Encryption required";
    else appName = "Plaintext USB copy";
    detail = `${event.resourcePath || "External Drive"}`;
  } else if (isOpticalEvent) {
    const isPhysicalOptical = event.action?.startsWith("optical-media");
    appName = isPhysicalOptical ? "Optical media mount" : "Disk image mount";
    detail = event.resourcePath || (isPhysicalOptical ? "CD/DVD media" : "Virtual disk image");
  } else if (isNearbyEvent) {
    const channel = event.action?.startsWith("bluetooth")
      ? "Bluetooth"
      : event.action?.startsWith("apple-sharing")
        ? "Apple nearby sharing"
        : "AirDrop";
    appName = `${channel} file transfer`;
    detail = `${event.resourcePath || "Protected file"}`;
  } else if (isPrinterEvent) {
    appName = event.action === "print-job-observed" ? "Print job observed" : "Printer queue";
    detail = event.resourcePath || "Unknown printer";
  } else if (isPrintToPDFEvent) {
    appName = event.resourcePath?.split("/").pop() || "PDF file output";
    detail = `${event.signingId || event.executablePath?.split("/").pop() || "Application"} · New PDF output`;
  } else if (isOCREvent) {
    appName = event.action === "screenshot-scan" ? "Screenshot OCR" : "Content OCR";
    const classifications = event.classifications?.length
      ? event.classifications.join(", ")
      : "No sensitive classification";
    detail = `${classifications} · ${event.recognizedCharacterCount || 0} characters · ${event.pageCount || 1} page${event.pageCount === 1 ? "" : "s"}`;
  } else if (isDiscoveryEvent) {
    if (event.action === "scan-completed") {
      appName = "Discovery scan completed";
      detail = event.pageURL || `Scan ${event.resourcePath || ""}`;
    } else {
      appName = event.resourcePath?.split("/").pop() || "Classified file";
      detail = `${event.classifications?.join(", ") || "Sensitive data"} · ${event.interaction || "at-rest scan"}`;
    }
  } else if (isNetworkFlowEvent) {
    appName = event.resourcePath || "Network socket";
    const proc = event.signingId || event.executablePath?.split("/").pop() || "unknown app";
    const proto = event.pageURL ? event.pageURL.toUpperCase() : "TCP";
    detail = `${proc} · ${proto} · Rule: ${event.ruleId || "default"}`;
  }

  const time = event.timestamp ? new Date(event.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";
  return (
    <div className="event-row">
      <span className={`decision-dot ${event.decision}`} />
      <div><strong>{appName}</strong><span>{detail}</span></div>
      <span className={`decision-badge ${event.decision}`}>{event.decision}</span>
      <time>{time}</time>
    </div>
  );
}

function App() {
  const [activeFeature, setActiveFeature] = useState("overview");
  const [snapshot, setSnapshot] = useState(null);
  const [apps, setApps] = useState([]);
  const [appsLoading, setAppsLoading] = useState(true);
  const [appsError, setAppsError] = useState("");
  const [events, setEvents] = useState([]);
  const [query, setQuery] = useState("");
  const [clipboardQuery, setClipboardQuery] = useState("");
  const [busyApp, setBusyApp] = useState(null);
  const [busyClipboardApp, setBusyClipboardApp] = useState(null);
  const [busyMode, setBusyMode] = useState(false);
  const [busyWebUpload, setBusyWebUpload] = useState(false);
  const [busyEmailAttachment, setBusyEmailAttachment] = useState(false);
  const [busyUSBStorage, setBusyUSBStorage] = useState(false);
  const [busyUSBEncryption, setBusyUSBEncryption] = useState(false);
  const [busyOpticalDiskImage, setBusyOpticalDiskImage] = useState(false);
  const [busyNearbyTransfer, setBusyNearbyTransfer] = useState(false);
  const [busyClipboardMode, setBusyClipboardMode] = useState(false);
  const [busyPrinter, setBusyPrinter] = useState(false);
  const [busyPrintToPDF, setBusyPrintToPDF] = useState(false);
  const [busyOCR, setBusyOCR] = useState(false);
  const [busyScreenshotOCR, setBusyScreenshotOCR] = useState(false);
  const [ocrReport, setOCRReport] = useState(null);
  const [busyDiscovery, setBusyDiscovery] = useState(false);
  const [busyNetworkFlow, setBusyNetworkFlow] = useState(false);
  const [busyNetworkAction, setBusyNetworkAction] = useState(false);
  const [busyRuleAction, setBusyRuleAction] = useState(false);
  const [ruleForm, setRuleForm] = useState({
    ruleId: "",
    domain: "",
    ipAddress: "",
    cidrRange: "",
    port: "",
    protocol: "any",
    signingId: "",
    action: "block"
  });
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [liveBlockedNotice, setLiveBlockedNotice] = useState(null);

  useEffect(() => {
    window.veloxOnLiveEvent = (event) => {
      setEvents(prev => {
        if (event.eventId && prev.some(e => e.eventId === event.eventId)) return prev;
        return [event, ...prev.slice(0, 49)];
      });
      if (event.decision === "blocked") {
        let label = event.executablePath?.split("/").pop() || event.signingId || "Resource";
        if (event.module === "web-upload-control") {
          label = event.resourcePath?.split("/").pop() || "Protected File";
        } else if (event.module === "email-attachment-control") {
          label = event.resourcePath?.split("/").pop() || "Classified attachment";
        } else if (event.module === "clipboard-control") {
          label = event.pageURL || event.signingId || "Clipboard copy";
        } else if (event.module === "usb-storage-control") {
          label = event.resourcePath || "USB Device";
        } else if (event.module === "usb-encryption-control") {
          label = event.resourcePath?.split("/").pop() || "USB Device";
        } else if (event.module === "optical-disk-image-control") {
          label = event.action?.startsWith("optical-media") ? "Optical media" : "Disk image";
        } else if (event.module === "nearby-transfer-control") {
          label = event.resourcePath?.split("/").pop() || "Protected File";
        } else if (event.module === "printer-control") {
          label = event.resourcePath || "Printer";
        } else if (event.module === "print-to-pdf-control") {
          label = event.resourcePath?.split("/").pop() || "PDF file output";
        } else if (event.module === "ocr-content-classification") {
          label = event.action === "screenshot-scan" ? "Sensitive screenshot" : "Sensitive visual document";
        } else if (event.module === "network-flow-control") {
          label = event.resourcePath || "Network Connection";
        }
        setLiveBlockedNotice({
          id: event.eventId || Date.now(),
          module: event.module,
          label: label,
          action: event.action
        });
      }
    };
    return () => {
      window.veloxOnLiveEvent = null;
    };
  }, []);

  useEffect(() => {
    if (!liveBlockedNotice) return;
    const t = setTimeout(() => setLiveBlockedNotice(null), 6000);
    return () => clearTimeout(t);
  }, [liveBlockedNotice]);

  const refreshSnapshot = useCallback(async () => {
    try {
      const value = await nativeCall("getSnapshot");
      setSnapshot(value);
      setError("");
    } catch (err) {
      setError(err.message);
    }
  }, []);

  const refreshEvents = useCallback(async () => {
    try {
      const value = await nativeCall("getEvents", { limit: 30 });
      setEvents(value.events || []);
    } catch {
      // The status banner already communicates connection failures.
    }
  }, []);

  const refreshApplications = useCallback(async (force = false) => {
    setAppsLoading(true);
    setAppsError("");
    try {
      const value = await nativeCall("listApplications", { refresh: force });
      setApps(value.apps || []);
    } catch (err) {
      setAppsError(err.message || "Application discovery failed.");
    } finally {
      setAppsLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshSnapshot();
    refreshEvents();
    refreshApplications();
    const timer = setInterval(() => {
      refreshSnapshot();
      refreshEvents();
    }, 3000);
    return () => clearInterval(timer);
  }, [refreshApplications, refreshEvents, refreshSnapshot]);

  const blockedSigningIds = useMemo(() => new Set(snapshot?.blockedSigningIds || []), [snapshot]);
  const blockedPaths = useMemo(() => new Set(snapshot?.blockedExecutablePaths || []), [snapshot]);
  const clipboardBlockedSigningIds = useMemo(() => new Set(snapshot?.clipboardBlockedSigningIds || []), [snapshot]);
  const clipboardBlockedPaths = useMemo(() => new Set(snapshot?.clipboardBlockedExecutablePaths || []), [snapshot]);
  const filteredApps = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return apps;
    return apps.filter(app => `${app.name} ${app.signingId} ${app.bundleIdentifier}`.toLowerCase().includes(needle));
  }, [apps, query]);
  const clipboardFilteredApps = useMemo(() => {
    const needle = clipboardQuery.trim().toLowerCase();
    if (!needle) return apps;
    return apps.filter(app => `${app.name} ${app.signingId} ${app.bundleIdentifier}`.toLowerCase().includes(needle));
  }, [apps, clipboardQuery]);

  const isBlocked = app => (app.signingId && blockedSigningIds.has(app.signingId.toLowerCase())) || blockedPaths.has(app.executablePath);
  const isClipboardBlocked = app => (app.signingId && clipboardBlockedSigningIds.has(app.signingId.toLowerCase())) || clipboardBlockedPaths.has(app.executablePath);

  async function changeMode(mode) {
    setBusyMode(true);
    setNotice("");
    try {
      const value = await nativeCall("setMode", { mode });
      setSnapshot(value);
      setNotice(`Policy is now ${modeCopy[mode].label.toLowerCase()}.`);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyMode(false);
    }
  }

  async function toggleApplication(app, blocked) {
    setBusyApp(app.executablePath);
    setNotice("");
    try {
      const value = await nativeCall("setApplicationBlocked", {
        signingId: app.signingId || "",
        executablePath: app.executablePath,
        displayName: app.name,
        blocked,
      });
      setSnapshot(value);
      setNotice(`${app.name} is now ${blocked ? "blocked" : "allowed"}.`);
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyApp(null);
    }
  }

  async function changeWebUploadMode(mode) {
    setBusyWebUpload(true);
    setNotice("");
    try {
      const value = await nativeCall("setWebUploadMode", { mode });
      setSnapshot(value);
      setNotice(`Browser upload protection is now ${modeCopy[mode].label.toLowerCase()}.`);
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyWebUpload(false);
    }
  }

  async function changeEmailAttachmentConfig(mode, protectedClassifications = emailProtectedClassifications) {
    setBusyEmailAttachment(true);
    setNotice("");
    try {
      const mailClients = [
        { ruleId: "email-apple-mail", signingId: "com.apple.mail", isPlatformBinary: true },
        { ruleId: "email-microsoft-outlook", signingId: "com.microsoft.Outlook", teamId: "UBF8T346G9" },
      ];
      const value = await nativeCall("setEmailAttachmentConfig", {
        config: { mode, mailClients, protectedClassifications },
      });
      setSnapshot(value);
      setNotice(`Native email attachment protection is now ${modeCopy[mode].label.toLowerCase()}.`);
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyEmailAttachment(false);
    }
  }

  function toggleEmailClassification(classification) {
    const selected = emailProtectedClassifications.length
      ? emailProtectedClassifications
      : ocrClassifications;
    const next = selected.includes(classification)
      ? selected.filter(value => value !== classification)
      : [...selected, classification];
    changeEmailAttachmentConfig(emailAttachmentMode, next.length === ocrClassifications.length ? [] : next);
  }

  async function changeUSBStorageMode(mode) {
    setBusyUSBStorage(true);
    setNotice("");
    try {
      const value = await nativeCall("setUSBStorageMode", { mode });
      setSnapshot(value);
      setNotice(`USB storage protection is now ${modeCopy[mode].label.toLowerCase()}.`);
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyUSBStorage(false);
    }
  }

  async function changeUSBEncryptionMode(mode) {
    setBusyUSBEncryption(true);
    setNotice("");
    setError("");
    try {
      const value = await nativeCall("setUSBEncryptionMode", { mode });
      setSnapshot(value);
      setNotice(`USB encrypted-container protection is now ${modeCopy[mode].label.toLowerCase()}.`);
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyUSBEncryption(false);
    }
  }

  async function changeOpticalDiskImageConfig(changes) {
    setBusyOpticalDiskImage(true);
    setNotice("");
    setError("");
    try {
      const config = {
        mode: opticalDiskImageMode,
        blockDiskImages: opticalDiskImageBlocksDiskImages,
        blockOpticalMedia: opticalDiskImageBlocksOpticalMedia,
        ...changes,
      };
      const value = await nativeCall("setOpticalDiskImageConfig", { config });
      setSnapshot(value);
      setNotice(`Optical and disk-image protection is now ${modeCopy[config.mode].label.toLowerCase()}.`);
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyOpticalDiskImage(false);
    }
  }

  async function changeNearbyTransferMode(mode) {
    setBusyNearbyTransfer(true);
    setNotice("");
    try {
      const value = await nativeCall("setNearbyTransferMode", { mode });
      setSnapshot(value);
      setNotice(`Nearby transfer protection is now ${modeCopy[mode].label.toLowerCase()}.`);
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyNearbyTransfer(false);
    }
  }

  async function changeClipboardMode(mode) {
    setBusyClipboardMode(true);
    setNotice("");
    try {
      const value = await nativeCall("setClipboardMode", { mode });
      setSnapshot(value);
      setNotice(`Clipboard Control is now ${clipboardModeCopy[mode].label.toLowerCase()}.`);
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyClipboardMode(false);
    }
  }

  async function changePrinterMode(mode) {
    setBusyPrinter(true);
    setNotice("");
    setError("");
    try {
      const value = await nativeCall("setPrinterMode", { mode });
      setSnapshot(value);
      if (value.printerLastError) {
        setError(`Printer policy was saved, but CUPS enforcement reported: ${value.printerLastError}`);
      } else {
        setNotice(`Printer Control is now ${modeCopy[mode].label.toLowerCase()}.`);
      }
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyPrinter(false);
    }
  }

  async function changePrintToPDFMode(mode) {
    setBusyPrintToPDF(true);
    setNotice("");
    setError("");
    try {
      const value = await nativeCall("setPrintToPDFMode", { mode });
      setSnapshot(value);
      setNotice(`Print-to-PDF / File Control is now ${modeCopy[mode].label.toLowerCase()}.`);
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyPrintToPDF(false);
    }
  }

  async function changeOCRMode(mode) {
    setBusyOCR(true);
    setNotice("");
    setError("");
    try {
      const value = await nativeCall("setOCRMode", { mode });
      setSnapshot(value);
      setNotice(`Image and scanned-PDF classification is now ${modeCopy[mode].label.toLowerCase()}.`);
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyOCR(false);
    }
  }

  async function changeScreenshotOCRMode(mode) {
    setBusyScreenshotOCR(true);
    setNotice("");
    setError("");
    try {
      const value = await nativeCall("setScreenshotOCRMode", { mode });
      setSnapshot(value);
      setNotice(`Screenshot OCR is now ${modeCopy[mode].label.toLowerCase()}.`);
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyScreenshotOCR(false);
    }
  }

  async function scanOCRFile() {
    setBusyOCR(true);
    setOCRReport(null);
    setNotice("");
    setError("");
    try {
      const report = await nativeCall("scanOCRFile");
      setOCRReport(report);
      setNotice(`OCR analyzed ${report.fileName} locally without exposing extracted text.`);
      await refreshEvents();
    } catch (err) {
      if (err.message !== "OCR scan cancelled.") setError(err.message);
    } finally {
      setBusyOCR(false);
    }
  }

  async function changeEndpointDiscoveryConfig(patch) {
    setBusyDiscovery(true);
    setNotice("");
    setError("");
    try {
      const config = {
        mode: patch.mode ?? endpointDiscoveryMode,
        scheduleIntervalMinutes: patch.scheduleIntervalMinutes ?? endpointDiscoveryScheduleIntervalMinutes,
        includeLocalHome: patch.includeLocalHome ?? endpointDiscoveryIncludesLocalHome,
        includeMountedVolumes: patch.includeMountedVolumes ?? endpointDiscoveryIncludesMountedVolumes,
        includeMountedShares: patch.includeMountedShares ?? endpointDiscoveryIncludesMountedShares,
        tagClassifiedFiles: patch.tagClassifiedFiles ?? endpointDiscoveryTagsClassifiedFiles,
        maxFilesPerScan: patch.maxFilesPerScan ?? endpointDiscoveryMaxFilesPerScan,
      };
      const value = await nativeCall("setEndpointDiscoveryConfig", { config });
      setSnapshot(value);
      setNotice(`Endpoint Data Discovery is now ${modeCopy[config.mode].label.toLowerCase()}.`);
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyDiscovery(false);
    }
  }

  async function startEndpointDiscoveryScan() {
    setBusyDiscovery(true);
    setNotice("");
    setError("");
    try {
      const status = await nativeCall("startEndpointDiscoveryScan");
      setNotice(status.message || "Endpoint Data Discovery scan started.");
      await refreshSnapshot();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyDiscovery(false);
    }
  }

  async function openFullDiskAccessSettings() {
    try {
      const response = await nativeCall("openFullDiskAccessSettings");
      setNotice(response.message || "Full Disk Access settings opened.");
    } catch (err) {
      setError(err.message);
    }
  }

  async function changeNetworkFlowMode(mode) {
    setBusyNetworkFlow(true);
    setNotice("");
    setError("");
    try {
      const value = await nativeCall("setNetworkFlowMode", { mode });
      setSnapshot(value);
      setNotice(`Network Flow Control is now ${modeCopy[mode].label.toLowerCase()}.`);
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyNetworkFlow(false);
    }
  }

  async function changeNetworkFlowDefaultAction(defaultAction) {
    setBusyNetworkAction(true);
    setNotice("");
    setError("");
    try {
      const value = await nativeCall("setNetworkFlowDefaultAction", { defaultAction });
      setSnapshot(value);
      setNotice(`Network Flow default action is now ${defaultAction.toUpperCase()}.`);
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyNetworkAction(false);
    }
  }

  async function handleAddRule(e) {
    e.preventDefault();
    setBusyRuleAction(true);
    setNotice("");
    setError("");
    try {
      const rule = {
        ruleId: ruleForm.ruleId.trim() || `rule-${Date.now()}`,
        protocol: ruleForm.protocol || "any",
        action: ruleForm.action || "block",
      };
      if (ruleForm.domain.trim()) rule.domain = ruleForm.domain.trim();
      if (ruleForm.ipAddress.trim()) rule.ipAddress = ruleForm.ipAddress.trim();
      if (ruleForm.cidrRange.trim()) rule.cidrRange = ruleForm.cidrRange.trim();
      if (ruleForm.port.trim()) {
        const p = parseInt(ruleForm.port.trim(), 10);
        if (!isNaN(p) && String(p) === ruleForm.port.trim()) {
          rule.port = p;
        } else {
          rule.portRange = ruleForm.port.trim();
        }
      }
      if (ruleForm.signingId.trim()) {
        rule.process = {
          signingId: ruleForm.signingId.trim()
        };
      }
      if (!rule.domain && !rule.ipAddress && !rule.cidrRange && !rule.port && !rule.portRange && !rule.process) {
        throw new Error("Please specify at least one match criteria (Domain, IP, CIDR, Port, or Signing ID).");
      }
      const value = await nativeCall("addNetworkFlowRule", { rule });
      setSnapshot(value);
      setNotice(`Network rule '${rule.ruleId}' added successfully.`);
      setRuleForm({
        ruleId: "",
        domain: "",
        ipAddress: "",
        cidrRange: "",
        port: "",
        protocol: "any",
        signingId: "",
        action: "block"
      });
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyRuleAction(false);
    }
  }

  async function handleRemoveRule(ruleId) {
    setBusyRuleAction(true);
    setNotice("");
    setError("");
    try {
      const value = await nativeCall("removeNetworkFlowRule", { ruleId });
      setSnapshot(value);
      setNotice(`Network rule '${ruleId}' removed.`);
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyRuleAction(false);
    }
  }

  async function toggleClipboardApplication(app, blocked) {
    setBusyClipboardApp(app.executablePath);
    setNotice("");
    try {
      const value = await nativeCall("setClipboardApplicationBlocked", {
        signingId: app.signingId || "",
        executablePath: app.executablePath,
        displayName: app.name,
        blocked,
      });
      setSnapshot(value);
      setNotice(`${app.name} is ${blocked ? "now blocked from copying" : "now allowed to copy"}.`);
      await refreshEvents();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyClipboardApp(null);
    }
  }

  const online = snapshot?.extensionStatus === "enforcing";
  const mode = snapshot?.mode || "audit-only";
  const webUploadMode = snapshot?.webUploadMode || "disabled";
  const emailAttachmentMode = snapshot?.emailAttachmentMode || "disabled";
  const emailClientCount = snapshot?.emailClientCount || 0;
  const emailProtectedClassifications = snapshot?.emailProtectedClassifications || [];
  const emailCachedClassificationCount = snapshot?.emailCachedClassificationCount || 0;
  const usbStorageMode = snapshot?.usbStorageMode || "enforce";
  const usbEncryptionMode = snapshot?.usbEncryptionMode || "disabled";
  const usbExternalVolumeCount = snapshot?.usbExternalVolumeCount || 0;
  const usbEncryptedContainerCount = snapshot?.usbEncryptedContainerCount || 0;
  const opticalDiskImageMode = snapshot?.opticalDiskImageMode || "disabled";
  const opticalDiskImageBlocksDiskImages = snapshot?.opticalDiskImageBlocksDiskImages !== false;
  const opticalDiskImageBlocksOpticalMedia = snapshot?.opticalDiskImageBlocksOpticalMedia !== false;
  const nearbyTransferMode = snapshot?.nearbyTransferMode || "disabled";
  const clipboardMode = snapshot?.clipboardMode || "disabled";
  const printerMode = snapshot?.printerMode || "disabled";
  const printToPDFMode = snapshot?.printToPDFMode || "disabled";
  const printerQueueCount = snapshot?.printerQueueCount || 0;
  const printerControlledQueueCount = snapshot?.printerControlledQueueCount || 0;
  const ocrMode = snapshot?.ocrMode || "disabled";
  const screenshotOCRMode = snapshot?.screenshotOCRMode || "disabled";
  const screenshotOCRRemediation = snapshot?.screenshotOCRRemediation || "quarantine";
  const ocrRuleCount = snapshot?.ocrRuleCount || 0;
  const ocrRecognitionLanguages = snapshot?.ocrRecognitionLanguages || [];
  const ocrClassifications = snapshot?.ocrClassifications || [];
  const endpointDiscoveryMode = snapshot?.endpointDiscoveryMode || "disabled";
  const endpointDiscoveryScheduleIntervalMinutes = snapshot?.endpointDiscoveryScheduleIntervalMinutes || 1440;
  const endpointDiscoveryIncludesLocalHome = snapshot?.endpointDiscoveryIncludesLocalHome !== false;
  const endpointDiscoveryIncludesMountedVolumes = snapshot?.endpointDiscoveryIncludesMountedVolumes !== false;
  const endpointDiscoveryIncludesMountedShares = snapshot?.endpointDiscoveryIncludesMountedShares !== false;
  const endpointDiscoveryTagsClassifiedFiles = snapshot?.endpointDiscoveryTagsClassifiedFiles !== false;
  const endpointDiscoveryMaxFilesPerScan = snapshot?.endpointDiscoveryMaxFilesPerScan || 10000;
  const endpointDiscoveryRunning = snapshot?.endpointDiscoveryRunning === true;
  const endpointDiscoveryLastReport = snapshot?.endpointDiscoveryLastReport || null;
  const endpointDiscoveryNextScheduledAt = snapshot?.endpointDiscoveryNextScheduledAt || null;
  const networkFlowMode = snapshot?.networkFlowMode || "disabled";
  const networkFlowDefaultAction = snapshot?.networkFlowDefaultAction || "allow";
  const networkFlowRules = snapshot?.networkFlowRules || [];
  const networkFlowRuleCount = snapshot?.networkFlowRuleCount || 0;
  const networkFilterStatus = snapshot?.networkFilterStatus || "unknown";
  const networkFilterEnabled = snapshot?.networkFilterEnabled === true;
  const networkFilterStatusInfo = networkFilterStatusCopy[networkFilterStatus] || networkFilterStatusCopy.unknown;
  const blockedCount = snapshot?.blockedRuleCount || 0;
  const protectedFolders = snapshot?.webUploadProtectedDirectories || [];
  const nearbyProtectedFolders = snapshot?.nearbyTransferProtectedDirectories || [];
  const clipboardBlockedCount = snapshot?.clipboardBlockedRuleCount || 0;

  const visibleEvents = events.filter(event => {
    if (activeFeature === "web-upload") {
      return event.module === "web-upload-control";
    }
    if (activeFeature === "email") {
      return event.module === "email-attachment-control";
    }
    if (activeFeature === "usb-storage") {
      return event.module === "usb-storage-control" || event.module === "usb-encryption-control";
    }
    if (activeFeature === "optical-media") {
      return event.module === "optical-disk-image-control";
    }
    if (activeFeature === "nearby-transfer") {
      return event.module === "nearby-transfer-control";
    }
    if (activeFeature === "clipboard") {
      return event.module === "clipboard-control";
    }
    if (activeFeature === "printer") {
      return event.module === "printer-control" || event.module === "print-to-pdf-control";
    }
    if (activeFeature === "ocr") {
      return event.module === "ocr-content-classification";
    }
    if (activeFeature === "discovery") {
      return event.module === "endpoint-data-discovery";
    }
    if (activeFeature === "network-flow") {
      return event.module === "network-flow-control";
    }
    return event.module !== "web-upload-control" && event.module !== "email-attachment-control" && event.module !== "clipboard-control" && event.module !== "usb-storage-control" && event.module !== "usb-encryption-control" && event.module !== "optical-disk-image-control" && event.module !== "nearby-transfer-control" && event.module !== "printer-control" && event.module !== "print-to-pdf-control" && event.module !== "ocr-content-classification" && event.module !== "endpoint-data-discovery" && event.module !== "network-flow-control";
  });

  const recentUploadBlocks = events.filter(event => event.module === "web-upload-control" && event.decision === "blocked").length;
  const recentEmailBlocks = events.filter(event => event.module === "email-attachment-control" && event.decision === "blocked").length;
  const recentUSBBlocks = events.filter(event => event.module === "usb-storage-control" && event.decision === "blocked").length;
  const recentUSBEncryptionBlocks = events.filter(event => event.module === "usb-encryption-control" && event.decision === "blocked").length;
  const recentOpticalBlocks = events.filter(event => event.module === "optical-disk-image-control" && event.decision === "blocked").length;
  const recentNearbyBlocks = events.filter(event => event.module === "nearby-transfer-control" && event.decision === "blocked").length;
  const recentClipboardBlocks = events.filter(event => event.module === "clipboard-control" && event.decision === "blocked").length;
  const recentPrinterBlocks = events.filter(event => event.module === "printer-control" && event.decision === "blocked").length;
  const recentPrintToPDFBlocks = events.filter(event => event.module === "print-to-pdf-control" && event.decision === "blocked").length;
  const recentOCRBlocks = events.filter(event => event.module === "ocr-content-classification" && event.decision === "blocked").length;
  const recentDiscoveryFindings = events.filter(event => event.module === "endpoint-data-discovery" && event.action === "classified-file").length;
  const recentNetworkBlocks = events.filter(event => event.module === "network-flow-control" && event.decision === "blocked").length;
  const recentBlockedTotal = events.filter(event => event.decision === "blocked").length;

  const usbProtectionActive = usbStorageMode === "enforce" || usbEncryptionMode === "enforce";
  const printerProtectionActive = printerMode === "enforce" || printToPDFMode === "enforce";
  const printerProtectionAuditing = !printerProtectionActive && (printerMode === "audit-only" || printToPDFMode === "audit-only");
  const activeProtectionCount = snapshot ? [
    mode === "enforce",
    webUploadMode === "enforce",
    emailAttachmentMode === "enforce",
    usbProtectionActive,
    opticalDiskImageMode === "enforce",
    nearbyTransferMode === "enforce",
    clipboardMode !== "disabled",
    printerProtectionActive,
    ocrMode === "enforce" || screenshotOCRMode === "enforce",
    endpointDiscoveryMode === "enforce",
    networkFlowMode === "enforce" && networkFilterEnabled,
  ].filter(Boolean).length : 0;
  const protectionCoverage = Math.round((activeProtectionCount / 11) * 100);
  const auditOnlyCount = snapshot ? [
    mode,
    webUploadMode,
    emailAttachmentMode,
    usbEncryptionMode !== "disabled" ? usbEncryptionMode : usbStorageMode,
    opticalDiskImageMode,
    nearbyTransferMode,
    printerMode === "audit-only" || printToPDFMode === "audit-only" ? "audit-only" : "disabled",
    ocrMode === "audit-only" || screenshotOCRMode === "audit-only" ? "audit-only" : "disabled",
    endpointDiscoveryMode,
    networkFlowMode,
  ].filter(value => value === "audit-only").length : 0;
  const orderedEvents = useMemo(
    () => [...events].sort((left, right) => {
      const leftTime = left.timestamp ? new Date(left.timestamp).getTime() : 0;
      const rightTime = right.timestamp ? new Date(right.timestamp).getTime() : 0;
      return rightTime - leftTime;
    }),
    [events]
  );

  const overviewFeatures = [
    {
      id: "applications",
      icon: "applications",
      title: "Application Control",
      description: "Signed-identity execution policy",
      status: modeCopy[mode]?.label || "Unknown",
      detail: `${blockedCount} application${blockedCount === 1 ? "" : "s"} blocked`,
      tone: mode === "enforce" ? "secure" : mode === "audit-only" ? "watching" : "inactive",
    },
    {
      id: "web-upload",
      icon: "web-upload",
      title: "Web Upload",
      description: "Outbound browser file protection",
      status: modeCopy[webUploadMode]?.label || "Unknown",
      detail: `${recentUploadBlocks} recent block${recentUploadBlocks === 1 ? "" : "s"}`,
      tone: webUploadMode === "enforce" ? "secure" : webUploadMode === "audit-only" ? "watching" : "inactive",
    },
    {
      id: "email",
      icon: "email",
      title: "Email Attachments",
      description: "Classified native-mail file control",
      status: modeCopy[emailAttachmentMode]?.label || "Unknown",
      detail: `${emailCachedClassificationCount} classified file${emailCachedClassificationCount === 1 ? "" : "s"} cached`,
      tone: emailAttachmentMode === "enforce" ? "secure" : emailAttachmentMode === "audit-only" ? "watching" : "inactive",
    },
    {
      id: "usb-storage",
      icon: "usb-storage",
      title: "USB Storage",
      description: usbEncryptionMode === "enforce" ? "Encrypted-container workflow" : "Removable-media access policy",
      status: usbEncryptionMode === "enforce" ? "Encrypted" : modeCopy[usbStorageMode]?.label || "Unknown",
      detail: usbEncryptionMode === "enforce" ? `${usbEncryptedContainerCount}/${usbExternalVolumeCount} containers ready` : `${recentUSBBlocks} mount attempts blocked`,
      tone: usbProtectionActive ? "secure" : (usbStorageMode === "audit-only" || usbEncryptionMode === "audit-only") ? "watching" : "inactive",
    },
    {
      id: "optical-media",
      icon: "optical-media",
      title: "Optical & Disk Images",
      description: "DMG, ISO and optical-media mount control",
      status: modeCopy[opticalDiskImageMode]?.label || "Unknown",
      detail: `${recentOpticalBlocks} recent block${recentOpticalBlocks === 1 ? "" : "s"}`,
      tone: opticalDiskImageMode === "enforce" ? "secure" : opticalDiskImageMode === "audit-only" ? "watching" : "inactive",
    },
    {
      id: "nearby-transfer",
      icon: "nearby-transfer",
      title: "AirDrop & Bluetooth",
      description: "Outbound nearby-transfer protection",
      status: modeCopy[nearbyTransferMode]?.label || "Unknown",
      detail: `${recentNearbyBlocks} recent block${recentNearbyBlocks === 1 ? "" : "s"}`,
      tone: nearbyTransferMode === "enforce" ? "secure" : nearbyTransferMode === "audit-only" ? "watching" : "inactive",
    },
    {
      id: "clipboard",
      icon: "clipboard",
      title: "Clipboard",
      description: "User-session pasteboard control",
      status: clipboardModeCopy[clipboardMode]?.label || "Unknown",
      detail: clipboardMode === "block-selected-apps" ? `${clipboardBlockedCount} selected apps` : `${recentClipboardBlocks} recent blocks`,
      tone: clipboardMode !== "disabled" ? "secure" : "inactive",
    },
    {
      id: "printer",
      icon: "printer",
      title: "Printer Control",
      description: "Physical printing and PDF file output",
      status: printerProtectionActive ? "Enforce" : printerProtectionAuditing ? "Audit only" : "Disabled",
      detail: `${printerControlledQueueCount}/${printerQueueCount} queues · ${recentPrintToPDFBlocks} PDF blocks`,
      tone: printerProtectionActive ? "secure" : printerProtectionAuditing ? "watching" : "inactive",
    },
    {
      id: "ocr",
      icon: "ocr",
      title: "OCR Classification",
      description: "On-device image and scanned-PDF analysis",
      status: modeCopy[ocrMode]?.label || "Unknown",
      detail: `${ocrRuleCount} rules · ${recentOCRBlocks} recent blocks`,
      tone: ocrMode === "enforce" || screenshotOCRMode === "enforce"
        ? "secure"
        : ocrMode === "audit-only" || screenshotOCRMode === "audit-only"
          ? "watching"
          : "inactive",
    },
    {
      id: "discovery",
      icon: "discovery",
      title: "Data Discovery",
      description: "Scheduled at-rest classification",
      status: endpointDiscoveryRunning ? "Scanning" : modeCopy[endpointDiscoveryMode]?.label || "Unknown",
      detail: endpointDiscoveryLastReport
        ? `${endpointDiscoveryLastReport.findingsCount} finding${endpointDiscoveryLastReport.findingsCount === 1 ? "" : "s"} in last scan`
        : `${recentDiscoveryFindings} recent finding${recentDiscoveryFindings === 1 ? "" : "s"}`,
      tone: endpointDiscoveryMode === "enforce" ? "secure" : endpointDiscoveryMode === "audit-only" ? "watching" : "inactive",
    },
    {
      id: "network-flow",
      icon: "network-flow",
      title: "Network Flow Control",
      description: "Outbound socket & domain policy",
      status: networkFilterEnabled ? (modeCopy[networkFlowMode]?.label || "Unknown") : networkFilterStatusInfo.label,
      detail: networkFilterEnabled
        ? `${networkFlowRuleCount} rule${networkFlowRuleCount === 1 ? "" : "s"} · Default ${networkFlowDefaultAction.toUpperCase()}`
        : networkFilterStatusInfo.detail,
      tone: networkFilterEnabled && networkFlowMode === "enforce" ? "secure" : networkFilterEnabled && networkFlowMode === "audit-only" ? "watching" : "inactive",
    },
  ];
  const visibleOverviewFeatures = snapshot ? overviewFeatures : overviewFeatures.map(feature => ({
    ...feature,
    status: "Unavailable",
    tone: "inactive",
  }));

  const featureMeta = {
    "overview": {
      title: "Security Overview",
      subtitle: "Live protection posture and activity for this Mac."
    },
    "applications": {
      title: "Application Control",
      subtitle: "Control which applications can run on this endpoint."
    },
    "web-upload": {
      title: "Web Upload Control",
      subtitle: "Prevent protected files from leaving this Mac through supported browsers."
    },
    "email": {
      title: "Email Attachment Control",
      subtitle: "Stop already-classified files from being attached through trusted native mail clients."
    },
    "usb-storage": {
      title: "USB Removable Media Control",
      subtitle: "Block removable storage or require all outbound files to use an encrypted container."
    },
    "optical-media": {
      title: "Optical & Disk Image Control",
      subtitle: "Prevent DMG, ISO, sparse image, CD and DVD volumes from mounting."
    },
    "nearby-transfer": {
      title: "AirDrop & Bluetooth Control",
      subtitle: "Prevent protected files from being read by nearby file-transfer services."
    },
    "clipboard": {
      title: "Clipboard Control",
      subtitle: "Monitor clipboard activity and stop copying globally or from selected applications."
    },
    "printer": {
      title: "Printer Control",
      subtitle: "Audit or block physical printing through the local macOS print system."
    },
    "ocr": {
      title: "OCR Content Classification",
      subtitle: "Recognize sensitive text in images, scanned PDFs, and screenshots entirely on this Mac."
    },
    "discovery": {
      title: "Endpoint Data Discovery",
      subtitle: "Schedule at-rest scans across local user data, mounted volumes, and network shares."
    },
    "network-flow": {
      title: "Network Flow Control",
      subtitle: "Inspect outbound socket connections and enforce domain, IP, CIDR, and port policies."
    }
  }[activeFeature] || { title: "DLP Control", subtitle: "" };

  return (
    <div className={`shell ${activeFeature === "overview" ? "overview-shell" : ""}`}>
      <aside>
        <div className="brand"><ShieldMark /><div><strong>Velox</strong><span>Mac DLP</span></div></div>
        <nav>
          <button className={activeFeature === "overview" ? "active" : ""} onClick={() => setActiveFeature("overview")}><span>⌂</span>Overview</button>
          <button className={activeFeature === "applications" ? "active" : ""} onClick={() => setActiveFeature("applications")}><span>▦</span>Application Control</button>
          <button className={activeFeature === "web-upload" ? "active" : ""} onClick={() => setActiveFeature("web-upload")}><span>⇧</span>Web Upload Control</button>
          <button className={activeFeature === "email" ? "active" : ""} onClick={() => setActiveFeature("email")}><span>✉</span>Email Attachment Control</button>
          <button className={activeFeature === "clipboard" ? "active" : ""} onClick={() => setActiveFeature("clipboard")}><span>▣</span>Clipboard Control</button>
          <button className={activeFeature === "printer" ? "active" : ""} onClick={() => setActiveFeature("printer")}><span>▤</span>Printer Control</button>
          <button className={activeFeature === "ocr" ? "active" : ""} onClick={() => setActiveFeature("ocr")}><span>⌗</span>OCR Classification</button>
          <button className={activeFeature === "discovery" ? "active" : ""} onClick={() => setActiveFeature("discovery")}><span>⌕</span>Data Discovery</button>
          <button className={activeFeature === "usb-storage" ? "active" : ""} onClick={() => setActiveFeature("usb-storage")}><span>⏏</span>USB Storage Control</button>
          <button className={activeFeature === "optical-media" ? "active" : ""} onClick={() => setActiveFeature("optical-media")}><span>◉</span>Optical & Disk Images</button>
          <button className={activeFeature === "nearby-transfer" ? "active" : ""} onClick={() => setActiveFeature("nearby-transfer")}><span>⌁</span>AirDrop & Bluetooth</button>
          <button className={activeFeature === "network-flow" ? "active" : ""} onClick={() => setActiveFeature("network-flow")}><span>☍</span>Network Flow</button>
          <button disabled><span>≋</span>Activity</button>
          <button disabled><span>⚙</span>Agent Settings</button>
        </nav>
        <div className="sidebar-status"><StatusPill online={online} /><span>VeloxMacDLP</span></div>
      </aside>

      <main>
        <header className={activeFeature === "overview" ? "overview-page-header" : ""}>
          <div>
            <p className="eyebrow">ENDPOINT / THIS MAC</p>
            <h1>{featureMeta.title}</h1>
            <p>{featureMeta.subtitle}</p>
          </div>
          <StatusPill online={online} />
        </header>

        {error && <div className="banner error"><strong>Control service unavailable</strong><span>{error}</span></div>}
        {notice && <div className="banner success"><strong>Policy activated</strong><span>{notice}</span></div>}
        {liveBlockedNotice && (
          <div className="banner error live-blocked-banner" role="alert" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderLeft: "4px solid #ff4d5e", background: "rgba(255, 77, 94, 0.15)", marginBottom: "16px" }}>
            <div>
              <strong style={{ color: "#ff4d5e" }}>⛔ BLOCKED BY VELOX DLP</strong>
              <span style={{ marginLeft: "8px" }}>'{liveBlockedNotice.label}' was blocked by security policy.</span>
            </div>
            <button
              onClick={() => setLiveBlockedNotice(null)}
              style={{ background: "none", border: "none", color: "#8b949e", cursor: "pointer", fontSize: "16px", padding: "0 8px" }}
              aria-label="Dismiss alert"
            >✕</button>
          </div>
        )}

        <div key={activeFeature} className="feature-view">
        {activeFeature === "overview" && <>
          <section className="overview-hero glass-surface">
            <span className="hero-aurora hero-aurora-one" />
            <span className="hero-aurora hero-aurora-two" />
            <div className="overview-hero-copy">
              <div className={`hero-state ${online ? "secure" : "attention"}`}><i />{online ? "Live local enforcement" : "Protection service offline"}</div>
              <h2>{online ? "Protection is active." : "This Mac needs attention."}</h2>
              <p>{online ? `Velox is enforcing the latest local policy across ${activeProtectionCount} of 11 control surfaces.` : "Reconnect the privileged security extension to restore policy enforcement."}</p>
              <div className="hero-meta">
                <span><b>v{snapshot?.policyVersion ?? "—"}</b> policy</span>
                <span><b>{recentBlockedTotal}</b> recent blocks</span>
                <span><b>{auditOnlyCount}</b> audit-only</span>
              </div>
              <button className="hero-action" onClick={() => setActiveFeature("applications")}><span>Manage protection</span><b>›</b></button>
            </div>
            <div className="protection-visual" aria-label={`${activeProtectionCount} of 11 controls active`}>
              <div className="coverage-orbit" style={{ "--coverage-degrees": `${protectionCoverage * 3.6}deg` }}>
                <div className="coverage-orbit-inner">
                  <ShieldMark />
                  <strong>{activeProtectionCount}<span>/11</span></strong>
                  <small>controls active</small>
                </div>
              </div>
              <span className={`orbit-caption ${online ? "secure" : "attention"}`}><i />Endpoint Security {online ? "connected" : "offline"}</span>
            </div>
          </section>

          <section className="overview-stat-strip glass-surface" aria-label="Endpoint summary">
            <div><span className="stat-icon secure">✓</span><span><small>Agent status</small><strong>{online ? "Protected" : "Offline"}</strong></span></div>
            <div><span className="stat-icon violet">⌁</span><span><small>Protection coverage</small><strong>{protectionCoverage}% active</strong></span></div>
            <div><span className="stat-icon amber">↗</span><span><small>Recent decisions</small><strong>{recentBlockedTotal} blocked</strong></span></div>
            <div><span className="stat-icon blue">◆</span><span><small>Policy revision</small><strong>Version {snapshot?.policyVersion ?? "—"}</strong></span></div>
          </section>

          <div className="overview-section-heading">
            <div><span>PROTECTION LAYERS</span><h2>Your security controls</h2></div>
            <p>Select a control to review its policy and activity.</p>
          </div>
          <section className="overview-feature-grid">
            {visibleOverviewFeatures.map(feature => (
              <OverviewFeatureCard
                key={feature.id}
                {...feature}
                onOpen={() => setActiveFeature(feature.id)}
              />
            ))}
          </section>

          <section className="overview-bottom-grid">
            <article className="overview-activity-card glass-surface">
              <div className="overview-card-heading">
                <div><span>LIVE SIGNAL</span><h2>Recent activity</h2></div>
                <button className="glass-icon-button" onClick={refreshEvents} aria-label="Refresh activity">↻</button>
              </div>
              <div className="overview-event-list">
                {orderedEvents.slice(0, 5).map(event => <EventRow key={event.eventId} event={event} />)}
                {!orderedEvents.length && <div className="overview-empty"><span>✓</span><strong>All quiet</strong><p>New security decisions will appear here.</p></div>}
              </div>
            </article>

            <article className="overview-health-card glass-surface">
              <div className="overview-card-heading"><div><span>THIS MAC</span><h2>Agent health</h2></div><span className={`health-badge ${online ? "secure" : "attention"}`}>{online ? "Healthy" : "Attention"}</span></div>
              <div className="health-visual">
                <div className={`health-pulse ${online ? "secure" : "attention"}`}><span /><i /></div>
                <div><strong>{online ? "Systems operational" : "Connection interrupted"}</strong><p>{online ? "Policies are evaluated locally, including while the backend is unavailable." : "Open the agent status details and reconnect the extension."}</p></div>
              </div>
              <div className="health-list">
                <div><span>Endpoint Security</span><strong className={online ? "secure-text" : "attention-text"}><i />{online ? "Connected" : "Offline"}</strong></div>
                <div><span>Policy engine</span><strong>Local · v{snapshot?.policyVersion ?? "—"}</strong></div>
                <div><span>Protected surfaces</span><strong>{activeProtectionCount} active · {auditOnlyCount} auditing</strong></div>
                <div><span>Connected removable media</span><strong>{usbExternalVolumeCount}</strong></div>
              </div>
            </article>
          </section>
        </>}

        {activeFeature === "applications" && <>
          <section className="summary-grid">
            <article><span className="card-label">PROTECTION MODE</span><strong>{modeCopy[mode]?.label}</strong><p>{modeCopy[mode]?.detail}</p></article>
            <article><span className="card-label">BLOCKED APPLICATIONS</span><strong>{blockedCount}</strong><p>Signing identities currently denied.</p></article>
            <article><span className="card-label">POLICY VERSION</span><strong>v{snapshot?.policyVersion ?? "—"}</strong><p>Applied by the Endpoint Security extension.</p></article>
          </section>

          <section className="panel mode-panel">
            <div><h2>Enforcement mode</h2><p>Policy changes are applied immediately by the privileged extension.</p></div>
            <div className="segmented">
              {Object.entries(modeCopy).map(([value, copy]) => (
                <button key={value} className={mode === value ? "selected" : ""} disabled={busyMode || !online} onClick={() => changeMode(value)}>{copy.label}</button>
              ))}
            </div>
          </section>

          <section className="panel applications-panel">
            <div className="panel-heading">
              <div>
                <h2>Applications</h2>
                <p>{appsLoading && !apps.length
                  ? "Discovering installed applications…"
                  : appsError && !apps.length
                    ? "Application discovery needs another attempt."
                    : `${apps.length} applications discovered on this Mac`}</p>
              </div>
              <div className="application-tools">
                <button className="app-refresh" disabled={appsLoading} onClick={() => refreshApplications(true)}>{appsLoading ? "Scanning…" : "Refresh"}</button>
                <label className="search"><span>⌕</span><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search applications" /></label>
              </div>
            </div>
            <div className="column-head"><span>APPLICATION</span><span>POLICY</span></div>
            <div className="app-list">
              {filteredApps.map(app => <AppRow key={app.executablePath} app={app} blocked={isBlocked(app)} busy={busyApp === app.executablePath} onToggle={toggleApplication} />)}
              {appsLoading && !apps.length && <div className="empty">Reading signed application identities from this Mac…</div>}
              {appsError && !apps.length && <div className="empty app-discovery-error"><strong>Application discovery failed</strong><span>{appsError}</span><button onClick={() => refreshApplications(true)}>Try again</button></div>}
              {!appsLoading && !appsError && !apps.length && <div className="empty app-discovery-error"><strong>No applications found</strong><span>Velox could not find application bundles in the standard macOS locations.</span><button onClick={() => refreshApplications(true)}>Scan again</button></div>}
              {!filteredApps.length && apps.length > 0 && <div className="empty">No applications match “{query}”.</div>}
            </div>
          </section>
        </>}

        {activeFeature === "web-upload" && <>
          <section className="summary-grid">
            <article><span className="card-label">UPLOAD PROTECTION</span><strong>{modeCopy[webUploadMode]?.label}</strong><p>Downloads and normal browser traffic remain allowed.</p></article>
            <article><span className="card-label">RECENTLY BLOCKED</span><strong>{recentUploadBlocks}</strong><p>Upload candidates in the current activity window.</p></article>
            <article><span className="card-label">ENFORCEMENT ENGINE</span><strong className="state-enabled">OS-Level Active</strong><p>Dual-layer kernel AUTH_OPEN + pasteboard guard protect all browsers.</p></article>
          </section>

          <section className="panel upload-panel">
            <div className="upload-heading">
              <div className="upload-icon">⇧</div>
              <div>
                <div className="title-with-badge"><h2>Browser upload protection</h2><span>OS-LEVEL DLP</span></div>
                <p>Stops file-picker, drag/drop and pasted-file uploads across all browsers (Safari, Chrome, Edge, Firefox, Brave) at the OS level. Incoming downloads remain allowed.</p>
              </div>
            </div>
            <div className="upload-controls">
              <div className="protected-folders">
                <span>PROTECTED FOLDERS ({protectedFolders.length})</span>
                <strong>{protectedFolders.join(" · ") || "Standard user folders"}</strong>
              </div>
              <div className="segmented">
                {Object.entries(modeCopy).map(([value, copy]) => (
                  <button key={value} className={webUploadMode === value ? "selected" : ""} disabled={busyWebUpload || !online} onClick={() => changeWebUploadMode(value)}>{copy.label}</button>
                ))}
              </div>
            </div>
          </section>

          <section className="panel coverage-panel">
            <div><span className="coverage-state">ALL BROWSERS ENFORCED</span><h2>Kernel Endpoint Security + Pasteboard Guard</h2><p>Protects Safari, Google Chrome, Microsoft Edge, Mozilla Firefox, Brave, and Opera. File access is intercepted at the kernel level (AUTH_OPEN) and clipboard transfers are intercepted upon browser activation. No browser extensions or user permissions needed.</p></div>
          </section>
        </>}

        {activeFeature === "email" && <>
          <section className="summary-grid">
            <article><span className="card-label">EMAIL POLICY</span><strong>{modeCopy[emailAttachmentMode]?.label}</strong><p>Applies to classified file reads by native mail clients.</p></article>
            <article><span className="card-label">CLASSIFIED FILE CACHE</span><strong>{emailCachedClassificationCount}</strong><p>Fresh discovery results currently enforceable.</p></article>
            <article><span className="card-label">RECENTLY BLOCKED</span><strong>{recentEmailBlocks}</strong><p>Native attachment candidates in the activity window.</p></article>
          </section>

          <section className="panel upload-panel">
            <div className="upload-heading">
              <div className="upload-icon">✉</div>
              <div>
                <div className="title-with-badge"><h2>Native email attachment protection</h2><span>CLASSIFICATION-AWARE</span></div>
                <p>Blocks Apple Mail and Microsoft Outlook from reading files that Endpoint Data Discovery has already classified. File downloads, message reading, and unclassified attachments remain allowed.</p>
              </div>
            </div>
            <div className="upload-controls">
              <div className="protected-folders">
                <span>TRUSTED CLIENT IDENTITIES</span>
                <strong>Apple Mail · Microsoft Outlook · {emailClientCount} signed rules</strong>
              </div>
              <div className="segmented">
                {Object.entries(modeCopy).map(([value, copy]) => (
                  <button key={value} className={emailAttachmentMode === value ? "selected" : ""} disabled={busyEmailAttachment || !online} onClick={() => changeEmailAttachmentConfig(value)}>{copy.label}</button>
                ))}
              </div>
            </div>
          </section>

          <section className="panel coverage-panel">
            <div>
              <span className="coverage-state">PROTECTED CLASSIFICATIONS</span>
              <h2>{emailProtectedClassifications.length ? "Selected sensitive-data classes" : "Every active OCR classification"}</h2>
              <p>Choose which discovery classifications are protected. An empty selection means all current and future active OCR classifications.</p>
              <div className="email-classification-list">
                {ocrClassifications.map(classification => {
                  const selected = !emailProtectedClassifications.length || emailProtectedClassifications.includes(classification);
                  return <button key={classification} className={selected ? "selected" : ""} disabled={busyEmailAttachment || !online} onClick={() => toggleEmailClassification(classification)}>{selected ? "✓ " : ""}{classification}</button>;
                })}
              </div>
            </div>
          </section>

          <section className="panel coverage-panel">
            <div>
              <span className="coverage-state warning">HONEST ENDPOINT BOUNDARY</span>
              <h2>Pre-egress file-read denial, not message inspection</h2>
              <p>macOS Endpoint Security does not expose a reliable Send event, recipients, subject, or attachment intent. Velox therefore denies a native mail client's read of a metadata-matched classified file before it can attach the bytes. Webmail uploads are controlled separately by Web Upload Control; recipient-aware policy belongs at the mail gateway.</p>
              <div className="email-cache-note"><strong>Coverage prerequisite</strong><span>Run Endpoint Data Discovery after installing this build. Modified files fail open until they are scanned again, preventing stale classifications from blocking unrelated content.</span></div>
            </div>
          </section>
        </>}

        {activeFeature === "usb-storage" && <>
          <section className="summary-grid">
            <article><span className="card-label">DEVICE ACCESS</span><strong>{modeCopy[usbStorageMode]?.label}</strong><p>{recentUSBBlocks} external mount attempts blocked.</p></article>
            <article><span className="card-label">ENCRYPTED CONTAINER</span><strong className={usbEncryptionMode === "enforce" ? "state-enabled" : ""}>{modeCopy[usbEncryptionMode]?.label}</strong><p>{recentUSBEncryptionBlocks} plaintext copy attempts blocked.</p></article>
            <article><span className="card-label">REMOVABLE VOLUMES</span><strong>{usbEncryptedContainerCount}/{usbExternalVolumeCount}</strong><p>Encrypted containers ready on connected physical volumes.</p></article>
          </section>

          <section className="panel upload-panel">
            <div className="upload-heading">
              <div className="upload-icon">⏏</div>
              <div>
                <div className="title-with-badge"><h2>USB & Type-C storage protection</h2><span>KERNEL DLP</span></div>
                <p>Blocks external flash drives, portable SSDs, and SD cards before macOS can mount them to /Volumes. Keyboards, mice, monitors, and Type-C chargers remain allowed.</p>
              </div>
            </div>
            <div className="upload-controls">
              <div className="protected-folders">
                <span>COVERED INTERFACES</span>
                <strong>USB-A · USB-C · Thunderbolt · SD Card Readers</strong>
              </div>
              <div className="segmented">
                {Object.entries(modeCopy).map(([value, copy]) => (
                  <button key={value} className={usbStorageMode === value ? "selected" : ""} disabled={busyUSBStorage || !online} onClick={() => changeUSBStorageMode(value)}>{copy.label}</button>
                ))}
              </div>
            </div>
          </section>

          <section className="panel upload-panel">
            <div className="upload-heading">
              <div className="upload-icon">⌘</div>
              <div>
                <div className="title-with-badge"><h2>USB encryption / container</h2><span>AES-256</span></div>
                <p>Allows the physical drive to mount, creates an encrypted APFS sparse container, and blocks direct plaintext writes to the outer drive. Users copy files into the mounted Velox Secure USB volume.</p>
              </div>
            </div>
            <div className="upload-controls">
              <div className="protected-folders">
                <span>CONTAINER PROFILE</span>
                <strong>APFS · AES-256 · {snapshot?.usbContainerSizePercent || 90}% virtual capacity</strong>
              </div>
              <div className="segmented">
                {Object.entries(modeCopy).map(([value, copy]) => (
                  <button key={value} className={usbEncryptionMode === value ? "selected" : ""} disabled={busyUSBEncryption || !online} onClick={() => changeUSBEncryptionMode(value)}>{copy.label}</button>
                ))}
              </div>
            </div>
          </section>

          {snapshot?.usbEncryptionLastError && <div className="banner error"><strong>Container unavailable</strong><span>{snapshot.usbEncryptionLastError}</span></div>}

          <section className="panel coverage-panel">
            <div><span className={`coverage-state ${usbEncryptionMode === "enforce" ? "warning" : ""}`}>{usbEncryptionMode === "enforce" ? "PLAINTEXT OUTER-VOLUME WRITES DENIED" : "KERNEL REMOVABLE-MEDIA CONTROL"}</span><h2>AUTH_MOUNT + AUTH_OPEN + AUTH_CREATE + AUTH_COPYFILE</h2><p>Device blocking and encrypted-container enforcement are mutually exclusive. Selecting container enforcement disables whole-device blocking, provisions VeloxSecure.sparsebundle, and permits only Apple's trusted disk-image processes to update that backing store. Recovery keys are root-only and local to this prototype; production must escrow wrapped device keys through the authenticated backend.</p></div>
          </section>
        </>}

        {activeFeature === "optical-media" && <>
          <section className="summary-grid">
            <article><span className="card-label">MOUNT POLICY</span><strong>{modeCopy[opticalDiskImageMode]?.label}</strong><p>Evaluated before a covered volume becomes available.</p></article>
            <article><span className="card-label">DISK IMAGES</span><strong className={opticalDiskImageBlocksDiskImages ? "state-enabled" : ""}>{opticalDiskImageBlocksDiskImages ? "Protected" : "Allowed"}</strong><p>DMG, ISO, sparse image and other virtual mounts.</p></article>
            <article><span className="card-label">OPTICAL MEDIA</span><strong className={opticalDiskImageBlocksOpticalMedia ? "state-enabled" : ""}>{opticalDiskImageBlocksOpticalMedia ? "Protected" : "Allowed"}</strong><p>Mounted CD, DVD and UDF-family filesystems.</p></article>
            <article><span className="card-label">RECENTLY BLOCKED</span><strong>{recentOpticalBlocks}</strong><p>Covered mount attempts in the activity window.</p></article>
          </section>

          <section className="panel mode-panel">
            <div><h2>Enforcement mode</h2><p>Enforce denies covered mounts. Audit only records the same decisions while allowing the volume.</p></div>
            <div className="segmented">
              {Object.entries(modeCopy).map(([value, copy]) => (
                <button
                  key={value}
                  className={opticalDiskImageMode === value ? "selected" : ""}
                  disabled={busyOpticalDiskImage || !online || (value !== "disabled" && !opticalDiskImageBlocksDiskImages && !opticalDiskImageBlocksOpticalMedia)}
                  onClick={() => changeOpticalDiskImageConfig({ mode: value })}
                >{copy.label}</button>
              ))}
            </div>
          </section>

          <section className="panel applications-panel">
            <div className="panel-heading"><div><h2>Controlled mount types</h2><p>Choose either route or protect both. At least one route remains selected while the policy is active.</p></div></div>
            <div className="discovery-scope-grid">
              <button
                className={`discovery-scope-card ${opticalDiskImageBlocksDiskImages ? "selected" : ""}`}
                disabled={busyOpticalDiskImage || !online || (opticalDiskImageMode !== "disabled" && opticalDiskImageBlocksDiskImages && !opticalDiskImageBlocksOpticalMedia)}
                onClick={() => changeOpticalDiskImageConfig({ blockDiskImages: !opticalDiskImageBlocksDiskImages })}
              >
                <span>{opticalDiskImageBlocksDiskImages ? "✓" : "○"}</span>
                <strong>Disk images</strong>
                <p>Virtual, file-backed mount candidates including DMG, ISO, sparseimage and sparsebundle containers.</p>
              </button>
              <button
                className={`discovery-scope-card ${opticalDiskImageBlocksOpticalMedia ? "selected" : ""}`}
                disabled={busyOpticalDiskImage || !online || (opticalDiskImageMode !== "disabled" && opticalDiskImageBlocksOpticalMedia && !opticalDiskImageBlocksDiskImages)}
                onClick={() => changeOpticalDiskImageConfig({ blockOpticalMedia: !opticalDiskImageBlocksOpticalMedia })}
              >
                <span>{opticalDiskImageBlocksOpticalMedia ? "✓" : "○"}</span>
                <strong>CD & DVD media</strong>
                <p>Physical optical volumes identified by CD9660, CDDA and UDF-family filesystem metadata.</p>
              </button>
            </div>
          </section>

          <section className="panel coverage-panel">
            <div>
              <span className={`coverage-state ${opticalDiskImageMode === "enforce" ? "warning" : ""}`}>{opticalDiskImageMode === "enforce" ? "PRE-MOUNT DENIAL ACTIVE" : opticalDiskImageMode === "audit-only" ? "MOUNT ACTIVITY AUDITED" : "CONTROL DISABLED"}</span>
              <h2>Endpoint Security AUTH_MOUNT enforcement</h2>
              <p>Velox identifies virtual mounts through Apple’s mount disposition and physical optical media through filesystem metadata, then decides before the mount completes. Internal disks, network shares and nullfs mounts are not classified as optical media. A narrow, time-limited allowance lets only Apple’s authenticated disk-image stack mount Velox Secure USB containers, so this control cannot break USB encryption.</p>
            </div>
          </section>
        </>}

        {activeFeature === "nearby-transfer" && <>
          <section className="summary-grid">
            <article><span className="card-label">NEARBY TRANSFER POLICY</span><strong>{modeCopy[nearbyTransferMode]?.label}</strong><p>Applies to outbound protected-file reads.</p></article>
            <article><span className="card-label">RECENTLY BLOCKED</span><strong>{recentNearbyBlocks}</strong><p>AirDrop and Bluetooth candidates in the activity window.</p></article>
            <article><span className="card-label">ENFORCEMENT ENGINE</span><strong className="state-enabled">Kernel AUTH_OPEN</strong><p>Incoming writes and ordinary Bluetooth accessories remain allowed.</p></article>
          </section>

          <section className="panel upload-panel">
            <div className="upload-heading">
              <div className="upload-icon">⌁</div>
              <div>
                <div className="title-with-badge"><h2>Nearby file-transfer protection</h2><span>PROTOTYPE</span></div>
                <p>Blocks read-only access to protected files by Apple sharingd/AirDrop and Bluetooth File Exchange/OBEX services. Receiving files is not blocked.</p>
              </div>
            </div>
            <div className="upload-controls">
              <div className="protected-folders">
                <span>PROTECTED FOLDERS ({nearbyProtectedFolders.length})</span>
                <strong>{nearbyProtectedFolders.join(" · ") || "Standard user folders"}</strong>
              </div>
              <div className="segmented">
                {Object.entries(modeCopy).map(([value, copy]) => (
                  <button key={value} className={nearbyTransferMode === value ? "selected" : ""} disabled={busyNearbyTransfer || !online} onClick={() => changeNearbyTransferMode(value)}>{copy.label}</button>
                ))}
              </div>
            </div>
          </section>

          <section className="panel coverage-panel">
            <div><span className="coverage-state warning">MANAGED DEPLOYMENT REQUIRED FOR FULL AIRDROP DISABLE</span><h2>Agent enforcement plus MDM restriction</h2><p>The agent blocks declared protected-file reads. Because sharingd also serves other Share Sheet destinations, those routes can be blocked too and are logged as Apple nearby sharing. For fleet-wide AirDrop disablement, deploy Apple's Restrictions payload with allowAirDrop=false through MDM. Bluetooth keyboards, mice, audio devices and incoming file writes are outside this policy.</p></div>
          </section>
        </>}

        {activeFeature === "clipboard" && <>
          <section className="summary-grid">
            <article><span className="card-label">CLIPBOARD POLICY</span><strong>{clipboardModeCopy[clipboardMode]?.label}</strong><p>{clipboardModeCopy[clipboardMode]?.detail}</p></article>
            <article><span className="card-label">SELECTED APPLICATIONS</span><strong>{clipboardBlockedCount}</strong><p>Signed source applications saved in policy.</p></article>
            <article><span className="card-label">MONITOR</span><strong className="state-enabled">User Session Active</strong><p>Detects normal macOS pasteboard changes within 100ms.</p></article>
          </section>

          <section className="panel mode-panel clipboard-mode-panel">
            <div><h2>Clipboard blocking scope</h2><p>Choose global blocking or restrict copying only from selected source applications.</p></div>
            <div className="segmented clipboard-segmented">
              {Object.entries(clipboardModeCopy).map(([value, copy]) => (
                <button key={value} className={clipboardMode === value ? "selected" : ""} disabled={busyClipboardMode || !online} onClick={() => changeClipboardMode(value)}>{copy.label}</button>
              ))}
            </div>
          </section>

          {clipboardMode === "block-selected-apps" && (
            <section className="panel applications-panel">
              <div className="panel-heading">
                <div><h2>Applications blocked from copying</h2><p>{clipboardBlockedCount ? `${clipboardBlockedCount} application${clipboardBlockedCount === 1 ? "" : "s"} selected` : "Select applications whose clipboard output must be cleared"}</p></div>
                <label className="search"><span>⌕</span><input value={clipboardQuery} onChange={event => setClipboardQuery(event.target.value)} placeholder="Search applications" /></label>
              </div>
              <div className="column-head"><span>SOURCE APPLICATION</span><span>CLIPBOARD POLICY</span></div>
              <div className="app-list">
                {clipboardFilteredApps.map(app => <ClipboardAppRow key={app.executablePath} app={app} selected={isClipboardBlocked(app)} busy={busyClipboardApp === app.executablePath} onToggle={toggleClipboardApplication} />)}
                {!clipboardFilteredApps.length && apps.length > 0 && <div className="empty">No applications match “{clipboardQuery}”.</div>}
              </div>
            </section>
          )}

          <section className="panel coverage-panel">
            <div>
              <span className={`coverage-state ${clipboardMode === "block-all" ? "warning" : ""}`}>{clipboardMode === "block-all" ? "ALL CLIPBOARD CONTENT CLEARED" : clipboardMode === "block-selected-apps" ? "SIGNED SOURCE APP MATCHING" : "MONITOR DISABLED"}</span>
              <h2>Privacy-safe clipboard enforcement</h2>
              <p>Velox never stores copied text, images, or file paths in clipboard telemetry. Activity records contain only the source application's signed identity, coarse content type, item count, and policy decision.</p>
              <div style={{ marginTop: "12px", padding: "10px 14px", borderRadius: "8px", background: "rgba(255, 255, 255, 0.05)", border: "1px solid rgba(255, 255, 255, 0.1)", fontSize: "12px", color: "#a0aab8" }}>
                <strong style={{ color: "#e2e8f0", display: "block", marginBottom: "4px" }}>macOS Platform Note & Limitations</strong>
                macOS Endpoint Security does not provide a kernel clipboard authorization event. Clipboard enforcement operates within the logged-in user agent by monitoring the system pasteboard and immediately clearing unauthorized content across keyboard shortcuts (⌘C), Edit menus, context menus, and drag/copy actions.
              </div>
            </div>
          </section>
        </>}

        {activeFeature === "printer" && <>
          <section className="summary-grid printer-summary-grid">
            <article><span className="card-label">PRINTER POLICY</span><strong>{modeCopy[printerMode]?.label}</strong><p>Applies to physical CUPS printer queues.</p></article>
            <article><span className="card-label">PRINT-TO-PDF POLICY</span><strong>{modeCopy[printToPDFMode]?.label}</strong><p>Controls new PDF files created by applications.</p></article>
            <article><span className="card-label">CONFIGURED QUEUES</span><strong>{printerQueueCount}</strong><p>{printerControlledQueueCount} currently controlled by Velox.</p></article>
            <article><span className="card-label">RECENTLY BLOCKED</span><strong>{recentPrinterBlocks + recentPrintToPDFBlocks}</strong><p>{recentPrinterBlocks} print · {recentPrintToPDFBlocks} PDF output.</p></article>
          </section>

          <section className="panel upload-panel">
            <div className="upload-heading">
              <div className="upload-icon">PDF</div>
              <div>
                <div className="title-with-badge"><h2>Print-to-PDF / File Control</h2><span>ENDPOINT SECURITY</span></div>
                <p>Enforce denies new PDF files created by applications in Desktop, Documents, Downloads, Movies, Music, Pictures, and Public. Audit only records the same attempts without interrupting them.</p>
              </div>
            </div>
            <div className="upload-controls">
              <div className="protected-folders">
                <span>DOWNLOAD SAFETY</span>
                <strong>Partial-download staging and final rename remain allowed</strong>
              </div>
              <div className="segmented">
                {Object.entries(modeCopy).map(([value, copy]) => (
                  <button key={value} className={printToPDFMode === value ? "selected" : ""} disabled={busyPrintToPDF || !online} onClick={() => changePrintToPDFMode(value)}>{copy.label}</button>
                ))}
              </div>
            </div>
          </section>

          <section className="panel upload-panel">
            <div className="upload-heading">
              <div className="upload-icon">▤</div>
              <div>
                <div className="title-with-badge"><h2>Physical printer protection</h2><span>CUPS QUEUE CONTROL</span></div>
                <p>Enforce rejects new jobs, stops every configured printer queue, and cancels jobs that are already queued. Velox checks again every second so newly added or re-enabled queues are brought back under policy.</p>
              </div>
            </div>
            <div className="upload-controls">
              <div className="protected-folders">
                <span>COVERED DESTINATIONS</span>
                <strong>USB · Network · AirPrint queues managed by CUPS</strong>
              </div>
              <div className="segmented">
                {Object.entries(modeCopy).map(([value, copy]) => (
                  <button key={value} className={printerMode === value ? "selected" : ""} disabled={busyPrinter || !online} onClick={() => changePrinterMode(value)}>{copy.label}</button>
                ))}
              </div>
            </div>
          </section>

          {snapshot?.printerLastError && <div className="banner error"><strong>CUPS enforcement needs attention</strong><span>{snapshot.printerLastError}</span></div>}

          <section className="panel coverage-panel">
            <div>
              <span className={`coverage-state ${printerMode === "enforce" ? "warning" : ""}`}>{printerMode === "enforce" ? "PHYSICAL PRINTING DISABLED" : printerMode === "audit-only" ? "PRINT JOBS AUDITED" : "PRINT CONTROL DISABLED"}</span>
              <h2>Queue-level protection with safe restoration</h2>
              <p>Velox saves each queue's original enabled and accepting state before changing it, then restores only queues changed by Velox when enforcement is disabled. Printer and job metadata are logged without document names or content.</p>
              <div style={{ marginTop: "12px", padding: "10px 14px", borderRadius: "8px", background: "rgba(255, 255, 255, 0.05)", border: "1px solid rgba(255, 255, 255, 0.1)", fontSize: "12px", color: "#a0aab8" }}>
                <strong style={{ color: "#e2e8f0", display: "block", marginBottom: "4px" }}>Prototype boundary</strong>
                Physical output uses CUPS queue control. Print-to-PDF uses Endpoint Security file authorization because macOS has no public print-dialog authorization event. It blocks direct new PDF output from desktop apps and browsers, including Save as PDF and equivalent app export paths; macOS does not reveal which UI command initiated the creation. Existing-file overwrites and atomic rename workflows require separate acceptance coverage.
              </div>
            </div>
          </section>
        </>}

        {activeFeature === "ocr" && <>
          <section className="summary-grid">
            <article><span className="card-label">DOCUMENT OCR</span><strong>{modeCopy[ocrMode]?.label}</strong><p>Images and scanned PDFs classified locally.</p></article>
            <article><span className="card-label">SCREENSHOT OCR</span><strong>{modeCopy[screenshotOCRMode]?.label}</strong><p>Detect-and-remediate after capture.</p></article>
            <article><span className="card-label">CLASSIFICATION RULES</span><strong>{ocrRuleCount}</strong><p>Payment card, PAN, Aadhaar and confidential markers.</p></article>
            <article><span className="card-label">LANGUAGES</span><strong>{ocrRecognitionLanguages.length || 1}</strong><p>{ocrRecognitionLanguages.join(", ") || "en-US"}</p></article>
          </section>

          <section className="panel mode-panel">
            <div><h2>Image and scanned-PDF policy</h2><p>Run on-device OCR and apply the configured content-classification rules.</p></div>
            <div className="segmented">
              {Object.entries(modeCopy).map(([value, copy]) => (
                <button key={value} className={ocrMode === value ? "selected" : ""} disabled={busyOCR || !online} onClick={() => changeOCRMode(value)}>{copy.label}</button>
              ))}
            </div>
          </section>

          <section className="panel mode-panel">
            <div><h2>Screenshot detection and remediation</h2><p>After Apple’s signed screenshot tool creates an image, classify it and {screenshotOCRRemediation === "delete" ? "delete" : "quarantine"} sensitive captures.</p></div>
            <div className="segmented">
              {Object.entries(modeCopy).map(([value, copy]) => (
                <button key={value} className={screenshotOCRMode === value ? "selected" : ""} disabled={busyScreenshotOCR || !online} onClick={() => changeScreenshotOCRMode(value)}>{copy.label}</button>
              ))}
            </div>
          </section>

          <section className="panel ocr-test-panel">
            <div className="ocr-test-heading">
              <div>
                <span className="coverage-state">LOCAL TEST</span>
                <h2>Test an image or scanned PDF</h2>
                <p>The native picker passes the file directly to Apple Vision and PDFKit. Recognized text stays in memory and is never shown in the console or written to logs.</p>
              </div>
              <button className="btn-add-rule ocr-scan-button" disabled={busyOCR || !online} onClick={scanOCRFile}>{busyOCR ? "Scanning…" : "Choose file to scan"}</button>
            </div>

            {ocrReport && (
              <div className={`ocr-result ${ocrReport.decision}`}>
                <div className="ocr-result-title">
                  <div><span>LAST RESULT</span><strong>{ocrReport.fileName}</strong></div>
                  <span className={`decision-badge ${ocrReport.decision}`}>{ocrReport.decision}</span>
                </div>
                <div className="ocr-result-metrics">
                  <div><span>Characters recognized</span><strong>{ocrReport.recognizedCharacterCount.toLocaleString()}</strong></div>
                  <div><span>Pages / frames</span><strong>{ocrReport.pageCount}</strong></div>
                  <div><span>Average confidence</span><strong>{Math.round(ocrReport.averageConfidence * 100)}%</strong></div>
                  <div><span>Processing</span><strong>{ocrReport.durationMillis} ms</strong></div>
                </div>
                <div className="ocr-classifications">
                  <span>CLASSIFICATIONS</span>
                  {ocrReport.matches.length
                    ? ocrReport.matches.map(match => <strong key={match.ruleId}>{match.classification}<small>{match.matchCount} match{match.matchCount === 1 ? "" : "es"}</small></strong>)
                    : <p>No configured sensitive-data rule matched this document.</p>}
                </div>
                <p className="ocr-privacy-note">Hash {ocrReport.contentHashPrefix} · {ocrReport.usedOCR ? "Apple Vision OCR" : "embedded PDF text"} · {ocrReport.cacheHit ? "memory cache hit" : "fresh analysis"}</p>
              </div>
            )}
          </section>

          <section className="panel coverage-panel">
            <div>
              <span className={`coverage-state ${screenshotOCRMode === "enforce" ? "warning" : ""}`}>{screenshotOCRMode === "enforce" ? "POST-CAPTURE REMEDIATION ACTIVE" : "ON-DEVICE CONTENT ANALYSIS"}</span>
              <h2>Accurate macOS boundary</h2>
              <p>OCR is intentionally asynchronous and never runs inside an Endpoint Security authorization deadline. Screenshot handling begins only after macOS creates the file, so this feature can quarantine sensitive captures but cannot prevent the pixels from existing briefly.</p>
            </div>
          </section>
        </>}

        {activeFeature === "discovery" && <>
          <section className="summary-grid">
            <article><span className="card-label">DISCOVERY POLICY</span><strong>{endpointDiscoveryRunning ? "Scanning…" : modeCopy[endpointDiscoveryMode]?.label}</strong><p>Scheduled at-rest classification.</p></article>
            <article><span className="card-label">LAST SCAN</span><strong>{endpointDiscoveryLastReport ? endpointDiscoveryLastReport.filesInspected.toLocaleString() : "—"}</strong><p>{endpointDiscoveryLastReport ? "supported files inspected" : "No completed scan yet"}</p></article>
            <article><span className="card-label">FINDINGS</span><strong>{endpointDiscoveryLastReport?.findingsCount ?? 0}</strong><p>Sensitive files in the latest report.</p></article>
            <article><span className="card-label">CLASSIFICATION TAGS</span><strong>{endpointDiscoveryLastReport?.taggedCount ?? 0}</strong><p>Velox xattrs applied in Enforce mode.</p></article>
          </section>

          <section className="panel mode-panel">
            <div><h2>Discovery mode</h2><p>Audit reports matches without changing files. Enforce also applies a Velox classification tag when supported by the filesystem.</p></div>
            <div className="segmented">
              {Object.entries(modeCopy).map(([value, copy]) => (
                <button key={value} className={endpointDiscoveryMode === value ? "selected" : ""} disabled={busyDiscovery || !online || endpointDiscoveryRunning} onClick={() => changeEndpointDiscoveryConfig({ mode: value })}>{copy.label}</button>
              ))}
            </div>
          </section>

          <section className="panel discovery-config-panel">
            <div className="panel-heading discovery-heading">
              <div><h2>Schedule and coverage</h2><p>Choose which user-visible storage locations are scanned using the active OCR/content rules.</p></div>
              <label className="discovery-schedule">
                <span>SCAN INTERVAL</span>
                <select className="form-select" value={endpointDiscoveryScheduleIntervalMinutes} disabled={busyDiscovery || endpointDiscoveryRunning} onChange={event => changeEndpointDiscoveryConfig({ scheduleIntervalMinutes: Number(event.target.value) })}>
                  <option value={15}>Every 15 minutes</option>
                  <option value={60}>Every hour</option>
                  <option value={360}>Every 6 hours</option>
                  <option value={1440}>Every day</option>
                  <option value={10080}>Every week</option>
                </select>
              </label>
            </div>
            <div className="discovery-scope-grid">
              {[
                ["includeLocalHome", endpointDiscoveryIncludesLocalHome, "Local user data", "Home folders and user-created content on this Mac"],
                ["includeMountedVolumes", endpointDiscoveryIncludesMountedVolumes, "Mounted local volumes", "External and removable filesystems currently mounted"],
                ["includeMountedShares", endpointDiscoveryIncludesMountedShares, "Mounted network shares", "Browsable SMB, AFP, and other non-local shares"],
              ].map(([key, enabled, title, detail]) => (
                <button key={key} className={`discovery-scope-card ${enabled ? "selected" : ""}`} aria-pressed={enabled} disabled={busyDiscovery || endpointDiscoveryRunning} onClick={() => changeEndpointDiscoveryConfig({ [key]: !enabled })}>
                  <span className="scope-check">{enabled ? "✓" : ""}</span>
                  <strong>{title}</strong>
                  <small>{detail}</small>
                </button>
              ))}
            </div>
            <button className={`discovery-tag-option ${endpointDiscoveryTagsClassifiedFiles ? "selected" : ""}`} aria-pressed={endpointDiscoveryTagsClassifiedFiles} disabled={busyDiscovery || endpointDiscoveryRunning} onClick={() => changeEndpointDiscoveryConfig({ tagClassifiedFiles: !endpointDiscoveryTagsClassifiedFiles })}>
              <span className="scope-check">{endpointDiscoveryTagsClassifiedFiles ? "✓" : ""}</span>
              <span><strong>Tag classified files</strong><small>Write <code>com.velox.macdlp.classification</code> metadata only in Enforce mode. Unsupported or read-only filesystems remain report-only.</small></span>
            </button>
          </section>

          <section className="panel discovery-run-panel">
            <div>
              <span className={`coverage-state ${endpointDiscoveryRunning ? "warning" : ""}`}>{endpointDiscoveryRunning ? "SCAN IN PROGRESS" : "ON-DEMAND SCAN"}</span>
              <h2>{endpointDiscoveryRunning ? "Velox is inspecting endpoint data" : "Run discovery now"}</h2>
              <p>Classification happens locally. Reports contain file paths, hashes, rule identifiers, and classifications—but never extracted text or file content.</p>
              {endpointDiscoveryNextScheduledAt && <small>Next scheduled scan: {new Date(endpointDiscoveryNextScheduledAt).toLocaleString()}</small>}
            </div>
            <div className="discovery-run-actions">
              <button className="setup-button" onClick={openFullDiskAccessSettings}>Full Disk Access</button>
              <button className="btn-add-rule" disabled={busyDiscovery || endpointDiscoveryRunning || endpointDiscoveryMode === "disabled" || !online} onClick={startEndpointDiscoveryScan}>{endpointDiscoveryRunning ? "Scanning…" : "Scan now"}</button>
            </div>
          </section>

          {endpointDiscoveryLastReport && (
            <section className="panel discovery-report-panel">
              <div className="panel-heading">
                <div>
                  <h2>Latest discovery report</h2>
                  <p>{new Date(endpointDiscoveryLastReport.completedAt).toLocaleString()} · {endpointDiscoveryLastReport.durationMillis.toLocaleString()} ms · {endpointDiscoveryLastReport.rootsScanned} root{endpointDiscoveryLastReport.rootsScanned === 1 ? "" : "s"}</p>
                </div>
                <span className={`coverage-state ${endpointDiscoveryLastReport.inaccessibleItems ? "warning" : ""}`}>{endpointDiscoveryLastReport.inaccessibleItems ? `${endpointDiscoveryLastReport.inaccessibleItems} INACCESSIBLE` : "SCAN COMPLETE"}</span>
              </div>
              <div className="discovery-report-metrics">
                <div><span>Enumerated</span><strong>{endpointDiscoveryLastReport.filesEnumerated.toLocaleString()}</strong></div>
                <div><span>Inspected</span><strong>{endpointDiscoveryLastReport.filesInspected.toLocaleString()}</strong></div>
                <div><span>Skipped</span><strong>{endpointDiscoveryLastReport.filesSkipped.toLocaleString()}</strong></div>
                <div><span>Findings</span><strong>{endpointDiscoveryLastReport.findingsCount.toLocaleString()}</strong></div>
                <div><span>Tagged</span><strong>{endpointDiscoveryLastReport.taggedCount.toLocaleString()}</strong></div>
              </div>
              <div className="discovery-findings">
                {endpointDiscoveryLastReport.findings.map(finding => (
                  <div className="discovery-finding-row" key={`${finding.contentHashPrefix}-${finding.filePath}`}>
                    <span className={`decision-dot ${finding.tagStatus === "tagged" ? "allowed" : "would-block"}`} />
                    <div><strong>{finding.fileName}</strong><span title={finding.filePath}>{finding.filePath}</span></div>
                    <span>{finding.classifications.join(", ")}</span>
                    <b className={`discovery-tag ${finding.tagStatus}`}>{finding.tagStatus}</b>
                  </div>
                ))}
                {!endpointDiscoveryLastReport.findings.length && <div className="empty">No sensitive content matched the active classification rules.</div>}
                {endpointDiscoveryLastReport.findingsTruncated && <div className="discovery-truncated">Showing the first 100 findings. The complete JSON report is stored at {endpointDiscoveryLastReport.reportPath}.</div>}
              </div>
            </section>
          )}

          <section className="panel coverage-panel">
            <div>
              <span className="coverage-state">FULL DISK ACCESS REQUIRED FOR COMPLETE COVERAGE</span>
              <h2>macOS discovery boundary</h2>
              <p>The scanner can only inspect files readable by the Velox host process. Grant Full Disk Access for protected user folders. Mounted shares must be connected and authenticated at scan time; read-only shares can be classified and reported but cannot be tagged.</p>
            </div>
          </section>
        </>}

        {activeFeature === "network-flow" && <>
          <section className="summary-grid">
            <article><span className="card-label">NETWORK POLICY</span><strong>{modeCopy[networkFlowMode]?.label}</strong><p>Outbound socket & domain evaluation.</p></article>
            <article><span className="card-label">DEFAULT ACTION</span><strong className={networkFlowDefaultAction === "block" ? "state-disabled" : "state-enabled"}>{networkFlowDefaultAction.toUpperCase()}</strong><p>Fallback for unmatched destinations.</p></article>
            <article><span className="card-label">ACTIVE RULES</span><strong>{networkFlowRuleCount}</strong><p>Domain, IP/CIDR & port filter rules.</p></article>
            <article><span className="card-label">SYSTEM FILTER</span><strong className={networkFilterEnabled ? "state-enabled" : "state-disabled"}>{networkFilterStatusInfo.label}</strong><p>{recentNetworkBlocks} recent flow{recentNetworkBlocks === 1 ? "" : "s"} blocked.</p></article>
          </section>

          {!networkFilterEnabled && networkFlowMode !== "disabled" && (
            <div className="banner error" role="alert">
              <strong>{networkFilterStatusInfo.label}</strong>
              <span>{snapshot?.networkFilterMessage || networkFilterStatusInfo.detail}</span>
            </div>
          )}

          <section className="panel mode-panel">
            <div><h2>Enforcement mode</h2><p>Control outbound socket connection enforcement across all processes.</p></div>
            <div className="segmented">
              {Object.entries(modeCopy).map(([value, copy]) => (
                <button key={value} className={networkFlowMode === value ? "selected" : ""} disabled={busyNetworkFlow || !online} onClick={() => changeNetworkFlowMode(value)}>{copy.label}</button>
              ))}
            </div>
          </section>

          <section className="panel mode-panel">
            <div><h2>Unmatched traffic default action</h2><p>Policy behavior when an outbound connection matches no specific rule.</p></div>
            <div className="segmented">
              <button className={networkFlowDefaultAction === "allow" ? "selected" : ""} disabled={busyNetworkAction || !online} onClick={() => changeNetworkFlowDefaultAction("allow")}>Default Allow</button>
              <button className={networkFlowDefaultAction === "block" ? "selected" : ""} disabled={busyNetworkAction || !online} onClick={() => changeNetworkFlowDefaultAction("block")}>Default Block</button>
            </div>
          </section>

          <section className="panel network-rules-panel">
            <div className="panel-heading">
              <div>
                <h2>Network Flow Rules ({networkFlowRules.length})</h2>
                <p>Filter connections by domain, IP/CIDR, port, transport protocol, and process identity.</p>
              </div>
            </div>

            <div className="rules-table-head">
              <span>RULE ID</span>
              <span>PROCESS</span>
              <span>DESTINATION</span>
              <span>PORT / PROTO</span>
              <span>ACTION</span>
              <span>MANAGE</span>
            </div>

            <div className="rules-list">
              {networkFlowRules.map(rule => {
                const destParts = [];
                if (rule.domain) destParts.push(rule.domain);
                if (rule.ipAddress) destParts.push(rule.ipAddress);
                if (rule.cidrRange) destParts.push(rule.cidrRange);
                const destStr = destParts.join(" · ") || "Any Destination";
                const portStr = rule.port ? String(rule.port) : (rule.portRange || "Any Port");
                const protoStr = (rule.protocol || "any").toUpperCase();
                const procStr = rule.process?.signingId || rule.process?.executablePath?.split("/").pop() || "All processes";

                return (
                  <div key={rule.ruleId} className="rule-row">
                    <span className="rule-id-text">{rule.ruleId}</span>
                    <span className="rule-process-text" title={procStr}>{procStr}</span>
                    <span className="rule-dest-text" title={destStr}>{destStr}</span>
                    <span className="rule-port-text">{portStr} <span className="rule-proto-tag">{protoStr}</span></span>
                    <span className={`rule-action-badge ${rule.action}`}>{rule.action.toUpperCase()}</span>
                    <button
                      className="btn-delete-rule"
                      disabled={busyRuleAction || !online}
                      onClick={() => handleRemoveRule(rule.ruleId)}
                      title={`Delete rule ${rule.ruleId}`}
                    >
                      Delete
                    </button>
                  </div>
                );
              })}
              {!networkFlowRules.length && (
                <div className="empty" style={{ padding: "20px 0" }}>
                  No network rules defined. All traffic falls back to default {networkFlowDefaultAction.toUpperCase()}.
                </div>
              )}
            </div>

            <div className="add-rule-card">
              <h3>Add Network Destination Rule</h3>
              <form onSubmit={handleAddRule} className="add-rule-form">
                <div className="add-rule-grid">
                  <div className="form-group">
                    <label>Rule ID (Optional)</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="e.g. block-cloud-storage"
                      value={ruleForm.ruleId}
                      onChange={e => setRuleForm(prev => ({ ...prev, ruleId: e.target.value }))}
                    />
                  </div>
                  <div className="form-group">
                    <label>Domain / Wildcard</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="e.g. dropbox.com, *.s3.amazonaws.com"
                      value={ruleForm.domain}
                      onChange={e => setRuleForm(prev => ({ ...prev, domain: e.target.value }))}
                    />
                  </div>
                  <div className="form-group">
                    <label>IP Address</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="e.g. 198.51.100.1"
                      value={ruleForm.ipAddress}
                      onChange={e => setRuleForm(prev => ({ ...prev, ipAddress: e.target.value }))}
                    />
                  </div>
                  <div className="form-group">
                    <label>CIDR Range</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="e.g. 10.0.0.0/8, 2001:db8::/32"
                      value={ruleForm.cidrRange}
                      onChange={e => setRuleForm(prev => ({ ...prev, cidrRange: e.target.value }))}
                    />
                  </div>
                  <div className="form-group">
                    <label>Port / Range</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="e.g. 443, 80-443, 8080"
                      value={ruleForm.port}
                      onChange={e => setRuleForm(prev => ({ ...prev, port: e.target.value }))}
                    />
                  </div>
                  <div className="form-group">
                    <label>Transport Protocol</label>
                    <select
                      className="form-select"
                      value={ruleForm.protocol}
                      onChange={e => setRuleForm(prev => ({ ...prev, protocol: e.target.value }))}
                    >
                      <option value="any">Any (TCP + UDP)</option>
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label>Process Signing ID (Optional)</label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="e.g. com.apple.Safari, curl"
                      value={ruleForm.signingId}
                      onChange={e => setRuleForm(prev => ({ ...prev, signingId: e.target.value }))}
                    />
                  </div>
                  <div className="form-group">
                    <label>Rule Action</label>
                    <select
                      className="form-select"
                      value={ruleForm.action}
                      onChange={e => setRuleForm(prev => ({ ...prev, action: e.target.value }))}
                    >
                      <option value="block">BLOCK</option>
                      <option value="allow">ALLOW (Whitelist)</option>
                    </select>
                  </div>
                </div>
                <div style={{ marginTop: "14px", display: "flex", justifyContent: "flex-end" }}>
                  <button
                    type="submit"
                    className="btn-add-rule"
                    disabled={busyRuleAction || !online}
                  >
                    {busyRuleAction ? "Saving..." : "+ Add Network Rule"}
                  </button>
                </div>
              </form>
            </div>
          </section>

          <section className="panel coverage-panel">
            <div>
              <span className={`coverage-state ${networkFlowMode === "enforce" && networkFilterEnabled ? "warning" : ""}`}>
                {!networkFilterEnabled ? networkFilterStatusInfo.label.toUpperCase() : networkFlowMode === "enforce" ? "KERNEL NETWORK FILTER ENFORCING" : networkFlowMode === "audit-only" ? "NETWORK FLOWS AUDITED" : "NETWORK POLICY DISABLED"}
              </span>
              <h2>Network Extension Content Filter & Flow Inspection</h2>
              <p>Network Flow Control runs in a dedicated system extension (<code>co.velox.macdlp.networkfilter</code>) using <code>NEFilterDataProvider</code> to inspect outbound socket connections across all user and system processes. Outbound connections are matched against Domain, IP/CIDR, Port, and Protocol rules with process code signature attribution.</p>
              <div style={{ marginTop: "12px", padding: "10px 14px", borderRadius: "8px", background: "rgba(255, 255, 255, 0.05)", border: "1px solid rgba(255, 255, 255, 0.1)", fontSize: "12px", color: "#a0aab8" }}>
                <strong style={{ color: "#e2e8f0", display: "block", marginBottom: "4px" }}>Fail-Open & Privacy Guarantees</strong>
                Critical macOS daemons (mDNSResponder, configd, trustd, launchd) and authentic Velox binaries are protected from blocking. If flow attribution cannot be resolved or evaluation errors occur, traffic safely fails open. Telemetry logs only destination hosts, IP addresses, ports, and signed process identities—network payloads and decrypted stream contents are never captured or logged.
              </div>
            </div>
          </section>
        </>}

        {activeFeature !== "overview" && <section className="panel activity-panel">
          <div className="panel-heading"><div><h2>Live activity</h2><p>{activeFeature === "usb-storage" ? "Latest USB mount, container, and plaintext-write decisions" : activeFeature === "optical-media" ? "Latest virtual disk-image and physical optical-media mount decisions" : activeFeature === "web-upload" ? "Latest browser file-transfer decisions from Endpoint Security" : activeFeature === "email" ? "Latest classified-file decisions for native mail clients" : activeFeature === "nearby-transfer" ? "Latest AirDrop and Bluetooth protected-file decisions" : activeFeature === "clipboard" ? "Latest clipboard copy decisions from the Velox user-session monitor" : activeFeature === "printer" ? "Latest physical print and PDF file-output decisions" : activeFeature === "ocr" ? "Latest on-device OCR classification decisions" : activeFeature === "discovery" ? "Latest scheduled and on-demand at-rest discovery findings" : activeFeature === "network-flow" ? "Latest outbound socket and network flow decisions from NetworkExtension" : "Latest application execution decisions from Endpoint Security"}</p></div><button className="refresh" onClick={refreshEvents}>Refresh</button></div>
          <div className="event-list">
            {visibleEvents.slice().reverse().slice(0, 12).map(event => <EventRow key={event.eventId} event={event} />)}
            {!visibleEvents.length && <div className="empty">No {activeFeature === "usb-storage" ? "USB storage" : activeFeature === "optical-media" ? "optical or disk-image mount" : activeFeature === "web-upload" ? "browser upload" : activeFeature === "email" ? "email attachment" : activeFeature === "nearby-transfer" ? "nearby transfer" : activeFeature === "clipboard" ? "clipboard" : activeFeature === "printer" ? "printer" : activeFeature === "ocr" ? "OCR classification" : activeFeature === "discovery" ? "endpoint discovery" : activeFeature === "network-flow" ? "network flow" : "application execution"} events recorded yet.</div>}
          </div>
        </section>}
        </div>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
