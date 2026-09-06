import React, { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
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
    const timeout = setTimeout(() => {
      pendingCalls.delete(id);
      reject(new Error("The security extension did not respond."));
    }, 8000);
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
      <svg viewBox="0 0 24 24"><path d="M12 2.4 20 5.6v5.7c0 5.1-3.3 8.7-8 10.3-4.7-1.6-8-5.2-8-10.3V5.6L12 2.4Zm0 3.1L7 7.4v3.9c0 3.4 1.9 5.9 5 7.2 3.1-1.3 5-3.8 5-7.2V7.4l-5-1.9Z" /></svg>
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
    "usb-storage": <><path d="M12 3v13" /><path d="m8.5 6.5 3.5-3.5 3.5 3.5" /><path d="M12 11 7.5 15.5" /><circle cx="7" cy="16" r="1.5" /><path d="M12 13.5 16.5 18" /><rect x="15.2" y="17.2" width="2.6" height="2.6" rx=".5" /><path d="M12 16v4" /><circle cx="12" cy="20" r="1" /></>,
    "nearby-transfer": <><circle cx="12" cy="12" r="1.6" /><path d="M8.2 8.2a5.4 5.4 0 0 0 0 7.6M15.8 8.2a5.4 5.4 0 0 1 0 7.6" /><path d="M5.2 5.2a9.6 9.6 0 0 0 0 13.6M18.8 5.2a9.6 9.6 0 0 1 0 13.6" /></>,
    clipboard: <><rect x="5" y="5.5" width="14" height="15" rx="2.5" /><path d="M9 5.5V4.4A1.4 1.4 0 0 1 10.4 3h3.2A1.4 1.4 0 0 1 15 4.4v1.1" /><path d="M8.5 11h7M8.5 15h5" /></>,
    printer: <><path d="M7 9V4h10v5" /><rect x="4" y="9" width="16" height="8" rx="2.5" /><path d="M7 15h10v5H7z" /><circle cx="17" cy="12" r=".8" /></>,
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
  const isClipboardEvent = event.module === "clipboard-control";
  const isUSBEvent = event.module === "usb-storage-control";
  const isUSBEncryptionEvent = event.module === "usb-encryption-control";
  const isNearbyEvent = event.module === "nearby-transfer-control";
  const isPrinterEvent = event.module === "printer-control";
  const isNetworkFlowEvent = event.module === "network-flow-control";
  let appName = event.executablePath?.split("/").pop() || event.signingId || "Unknown";
  let detail = event.signingId || event.executablePath;

  if (isUploadEvent) {
    appName = event.resourcePath?.split("/").pop() || "Protected file";
    detail = `${event.signingId || "Browser"} · ${event.resourcePath || "Unknown file"}`;
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
  const [events, setEvents] = useState([]);
  const [query, setQuery] = useState("");
  const [clipboardQuery, setClipboardQuery] = useState("");
  const [busyApp, setBusyApp] = useState(null);
  const [busyClipboardApp, setBusyClipboardApp] = useState(null);
  const [busyMode, setBusyMode] = useState(false);
  const [busyWebUpload, setBusyWebUpload] = useState(false);
  const [busyUSBStorage, setBusyUSBStorage] = useState(false);
  const [busyUSBEncryption, setBusyUSBEncryption] = useState(false);
  const [busyNearbyTransfer, setBusyNearbyTransfer] = useState(false);
  const [busyClipboardMode, setBusyClipboardMode] = useState(false);
  const [busyPrinter, setBusyPrinter] = useState(false);
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
        } else if (event.module === "clipboard-control") {
          label = event.pageURL || event.signingId || "Clipboard copy";
        } else if (event.module === "usb-storage-control") {
          label = event.resourcePath || "USB Device";
        } else if (event.module === "usb-encryption-control") {
          label = event.resourcePath?.split("/").pop() || "USB Device";
        } else if (event.module === "nearby-transfer-control") {
          label = event.resourcePath?.split("/").pop() || "Protected File";
        } else if (event.module === "printer-control") {
          label = event.resourcePath || "Printer";
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

  useEffect(() => {
    refreshSnapshot();
    refreshEvents();
    nativeCall("listApplications").then(value => setApps(value.apps || [])).catch(err => setError(err.message));
    const timer = setInterval(() => {
      refreshSnapshot();
      refreshEvents();
    }, 3000);
    return () => clearInterval(timer);
  }, [refreshEvents, refreshSnapshot]);

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
  const usbStorageMode = snapshot?.usbStorageMode || "enforce";
  const usbEncryptionMode = snapshot?.usbEncryptionMode || "disabled";
  const usbExternalVolumeCount = snapshot?.usbExternalVolumeCount || 0;
  const usbEncryptedContainerCount = snapshot?.usbEncryptedContainerCount || 0;
  const nearbyTransferMode = snapshot?.nearbyTransferMode || "disabled";
  const clipboardMode = snapshot?.clipboardMode || "disabled";
  const printerMode = snapshot?.printerMode || "disabled";
  const printerQueueCount = snapshot?.printerQueueCount || 0;
  const printerControlledQueueCount = snapshot?.printerControlledQueueCount || 0;
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
    if (activeFeature === "usb-storage") {
      return event.module === "usb-storage-control" || event.module === "usb-encryption-control";
    }
    if (activeFeature === "nearby-transfer") {
      return event.module === "nearby-transfer-control";
    }
    if (activeFeature === "clipboard") {
      return event.module === "clipboard-control";
    }
    if (activeFeature === "printer") {
      return event.module === "printer-control";
    }
    if (activeFeature === "network-flow") {
      return event.module === "network-flow-control";
    }
    return event.module !== "web-upload-control" && event.module !== "clipboard-control" && event.module !== "usb-storage-control" && event.module !== "usb-encryption-control" && event.module !== "nearby-transfer-control" && event.module !== "printer-control" && event.module !== "network-flow-control";
  });

  const recentUploadBlocks = events.filter(event => event.module === "web-upload-control" && event.decision === "blocked").length;
  const recentUSBBlocks = events.filter(event => event.module === "usb-storage-control" && event.decision === "blocked").length;
  const recentUSBEncryptionBlocks = events.filter(event => event.module === "usb-encryption-control" && event.decision === "blocked").length;
  const recentNearbyBlocks = events.filter(event => event.module === "nearby-transfer-control" && event.decision === "blocked").length;
  const recentClipboardBlocks = events.filter(event => event.module === "clipboard-control" && event.decision === "blocked").length;
  const recentPrinterBlocks = events.filter(event => event.module === "printer-control" && event.decision === "blocked").length;
  const recentNetworkBlocks = events.filter(event => event.module === "network-flow-control" && event.decision === "blocked").length;
  const recentBlockedTotal = events.filter(event => event.decision === "blocked").length;

  const usbProtectionActive = usbStorageMode === "enforce" || usbEncryptionMode === "enforce";
  const activeProtectionCount = snapshot ? [
    mode === "enforce",
    webUploadMode === "enforce",
    usbProtectionActive,
    nearbyTransferMode === "enforce",
    clipboardMode !== "disabled",
    printerMode === "enforce",
    networkFlowMode === "enforce" && networkFilterEnabled,
  ].filter(Boolean).length : 0;
  const protectionCoverage = Math.round((activeProtectionCount / 7) * 100);
  const auditOnlyCount = snapshot ? [
    mode,
    webUploadMode,
    usbEncryptionMode !== "disabled" ? usbEncryptionMode : usbStorageMode,
    nearbyTransferMode,
    printerMode,
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
      id: "usb-storage",
      icon: "usb-storage",
      title: "USB Storage",
      description: usbEncryptionMode === "enforce" ? "Encrypted-container workflow" : "Removable-media access policy",
      status: usbEncryptionMode === "enforce" ? "Encrypted" : modeCopy[usbStorageMode]?.label || "Unknown",
      detail: usbEncryptionMode === "enforce" ? `${usbEncryptedContainerCount}/${usbExternalVolumeCount} containers ready` : `${recentUSBBlocks} mount attempts blocked`,
      tone: usbProtectionActive ? "secure" : (usbStorageMode === "audit-only" || usbEncryptionMode === "audit-only") ? "watching" : "inactive",
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
      description: "Physical CUPS queue policy",
      status: modeCopy[printerMode]?.label || "Unknown",
      detail: `${printerControlledQueueCount}/${printerQueueCount} queues controlled`,
      tone: printerMode === "enforce" ? "secure" : printerMode === "audit-only" ? "watching" : "inactive",
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
    "usb-storage": {
      title: "USB Removable Media Control",
      subtitle: "Block removable storage or require all outbound files to use an encrypted container."
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
          <button className={activeFeature === "clipboard" ? "active" : ""} onClick={() => setActiveFeature("clipboard")}><span>▣</span>Clipboard Control</button>
          <button className={activeFeature === "printer" ? "active" : ""} onClick={() => setActiveFeature("printer")}><span>▤</span>Printer Control</button>
          <button className={activeFeature === "usb-storage" ? "active" : ""} onClick={() => setActiveFeature("usb-storage")}><span>⏏</span>USB Storage Control</button>
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
              <p>{online ? `Velox is enforcing the latest local policy across ${activeProtectionCount} of 7 control surfaces.` : "Reconnect the privileged security extension to restore policy enforcement."}</p>
              <div className="hero-meta">
                <span><b>v{snapshot?.policyVersion ?? "—"}</b> policy</span>
                <span><b>{recentBlockedTotal}</b> recent blocks</span>
                <span><b>{auditOnlyCount}</b> audit-only</span>
              </div>
              <button className="hero-action" onClick={() => setActiveFeature("applications")}><span>Manage protection</span><b>›</b></button>
            </div>
            <div className="protection-visual" aria-label={`${activeProtectionCount} of 7 controls active`}>
              <div className="coverage-orbit" style={{ "--coverage-degrees": `${protectionCoverage * 3.6}deg` }}>
                <div className="coverage-orbit-inner">
                  <ShieldMark />
                  <strong>{activeProtectionCount}<span>/7</span></strong>
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
              <div><h2>Applications</h2><p>{apps.length ? `${apps.length} applications discovered on this Mac` : "Discovering installed applications…"}</p></div>
              <label className="search"><span>⌕</span><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search applications" /></label>
            </div>
            <div className="column-head"><span>APPLICATION</span><span>POLICY</span></div>
            <div className="app-list">
              {filteredApps.map(app => <AppRow key={app.executablePath} app={app} blocked={isBlocked(app)} busy={busyApp === app.executablePath} onToggle={toggleApplication} />)}
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
          <section className="summary-grid">
            <article><span className="card-label">PRINTER POLICY</span><strong>{modeCopy[printerMode]?.label}</strong><p>Applies to physical CUPS printer queues.</p></article>
            <article><span className="card-label">CONFIGURED QUEUES</span><strong>{printerQueueCount}</strong><p>{printerControlledQueueCount} currently controlled by Velox.</p></article>
            <article><span className="card-label">RECENTLY BLOCKED</span><strong>{recentPrinterBlocks}</strong><p>Queue enforcement events in the activity window.</p></article>
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
                This phase blocks physical CUPS queues globally. Content classification and watermarking require a signed CUPS filter and OS-by-OS validation. Save as PDF does not use a physical printer queue and belongs to the separate Print-to-PDF control feature.
              </div>
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
          <div className="panel-heading"><div><h2>Live activity</h2><p>{activeFeature === "usb-storage" ? "Latest USB mount, container, and plaintext-write decisions" : activeFeature === "web-upload" ? "Latest browser file-transfer decisions from Endpoint Security" : activeFeature === "nearby-transfer" ? "Latest AirDrop and Bluetooth protected-file decisions" : activeFeature === "clipboard" ? "Latest clipboard copy decisions from the Velox user-session monitor" : activeFeature === "printer" ? "Latest physical printer queue and job decisions from CUPS" : activeFeature === "network-flow" ? "Latest outbound socket and network flow decisions from NetworkExtension" : "Latest application execution decisions from Endpoint Security"}</p></div><button className="refresh" onClick={refreshEvents}>Refresh</button></div>
          <div className="event-list">
            {visibleEvents.slice().reverse().slice(0, 12).map(event => <EventRow key={event.eventId} event={event} />)}
            {!visibleEvents.length && <div className="empty">No {activeFeature === "usb-storage" ? "USB storage" : activeFeature === "web-upload" ? "browser upload" : activeFeature === "nearby-transfer" ? "nearby transfer" : activeFeature === "clipboard" ? "clipboard" : activeFeature === "printer" ? "printer" : activeFeature === "network-flow" ? "network flow" : "application execution"} events recorded yet.</div>}
          </div>
        </section>}
        </div>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
