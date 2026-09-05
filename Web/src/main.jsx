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
  const isNearbyEvent = event.module === "nearby-transfer-control";
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
  } else if (isNearbyEvent) {
    const channel = event.action?.startsWith("bluetooth")
      ? "Bluetooth"
      : event.action?.startsWith("apple-sharing")
        ? "Apple nearby sharing"
        : "AirDrop";
    appName = `${channel} file transfer`;
    detail = `${event.resourcePath || "Protected file"}`;
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
  const [activeFeature, setActiveFeature] = useState("applications");
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
  const [busyNearbyTransfer, setBusyNearbyTransfer] = useState(false);
  const [busyClipboardMode, setBusyClipboardMode] = useState(false);
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
        } else if (event.module === "nearby-transfer-control") {
          label = event.resourcePath?.split("/").pop() || "Protected File";
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
  const nearbyTransferMode = snapshot?.nearbyTransferMode || "disabled";
  const clipboardMode = snapshot?.clipboardMode || "disabled";
  const blockedCount = snapshot?.blockedRuleCount || 0;
  const protectedFolders = snapshot?.webUploadProtectedDirectories || [];
  const nearbyProtectedFolders = snapshot?.nearbyTransferProtectedDirectories || [];
  const clipboardBlockedCount = snapshot?.clipboardBlockedRuleCount || 0;

  const visibleEvents = events.filter(event => {
    if (activeFeature === "web-upload") {
      return event.module === "web-upload-control";
    }
    if (activeFeature === "usb-storage") {
      return event.module === "usb-storage-control";
    }
    if (activeFeature === "nearby-transfer") {
      return event.module === "nearby-transfer-control";
    }
    if (activeFeature === "clipboard") {
      return event.module === "clipboard-control";
    }
    return event.module !== "web-upload-control" && event.module !== "clipboard-control" && event.module !== "usb-storage-control" && event.module !== "nearby-transfer-control";
  });

  const recentUploadBlocks = events.filter(event => event.module === "web-upload-control" && event.decision === "blocked").length;
  const recentUSBBlocks = events.filter(event => event.module === "usb-storage-control" && event.decision === "blocked").length;
  const recentNearbyBlocks = events.filter(event => event.module === "nearby-transfer-control" && event.decision === "blocked").length;
  const recentClipboardBlocks = events.filter(event => event.module === "clipboard-control" && event.decision === "blocked").length;

  const featureMeta = {
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
      subtitle: "Prevent unauthorized external USB and Type-C mass storage drives from mounting."
    },
    "nearby-transfer": {
      title: "AirDrop & Bluetooth Control",
      subtitle: "Prevent protected files from being read by nearby file-transfer services."
    },
    "clipboard": {
      title: "Clipboard Control",
      subtitle: "Monitor clipboard activity and stop copying globally or from selected applications."
    }
  }[activeFeature] || { title: "DLP Control", subtitle: "" };

  return (
    <div className="shell">
      <aside>
        <div className="brand"><ShieldMark /><div><strong>Velox</strong><span>Mac DLP</span></div></div>
        <nav>
          <button disabled><span>⌂</span>Overview</button>
          <button className={activeFeature === "applications" ? "active" : ""} onClick={() => setActiveFeature("applications")}><span>▦</span>Application Control</button>
          <button className={activeFeature === "web-upload" ? "active" : ""} onClick={() => setActiveFeature("web-upload")}><span>⇧</span>Web Upload Control</button>
          <button className={activeFeature === "clipboard" ? "active" : ""} onClick={() => setActiveFeature("clipboard")}><span>▣</span>Clipboard Control</button>
          <button className={activeFeature === "usb-storage" ? "active" : ""} onClick={() => setActiveFeature("usb-storage")}><span>⏏</span>USB Storage Control</button>
          <button className={activeFeature === "nearby-transfer" ? "active" : ""} onClick={() => setActiveFeature("nearby-transfer")}><span>⌁</span>AirDrop & Bluetooth</button>
          <button disabled><span>≋</span>Activity</button>
          <button disabled><span>⚙</span>Agent Settings</button>
        </nav>
        <div className="sidebar-status"><StatusPill online={online} /><span>VeloxMacDLP</span></div>
      </aside>

      <main>
        <header>
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
            <article><span className="card-label">USB PROTECTION</span><strong>{modeCopy[usbStorageMode]?.label}</strong><p>External USB & Type-C storage mounts.</p></article>
            <article><span className="card-label">BLOCKED MOUNTS</span><strong>{recentUSBBlocks}</strong><p>Blocked external drive mount attempts.</p></article>
            <article><span className="card-label">DISPOSITION ENGINE</span><strong className="state-enabled">Kernel AUTH_MOUNT</strong><p>Intercepts filesystem mounts at the kernel level.</p></article>
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

          <section className="panel coverage-panel">
            <div><span className="coverage-state">KERNEL DISPOSITION INVARIANT</span><h2>ES_MOUNT_DISPOSITION_EXTERNAL</h2><p>Endpoint Security checks each mount request's physical device disposition. Internal APFS system partitions and application translocations are guaranteed safe, while external mass storage volumes are denied at the Darwin VFS boundary.</p></div>
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

        <section className="panel activity-panel">
          <div className="panel-heading"><div><h2>Live activity</h2><p>{activeFeature === "usb-storage" ? "Latest USB storage mount decisions from Endpoint Security" : activeFeature === "web-upload" ? "Latest browser file-transfer decisions from Endpoint Security" : activeFeature === "nearby-transfer" ? "Latest AirDrop and Bluetooth protected-file decisions" : activeFeature === "clipboard" ? "Latest clipboard copy decisions from the Velox user-session monitor" : "Latest application execution decisions from Endpoint Security"}</p></div><button className="refresh" onClick={refreshEvents}>Refresh</button></div>
          <div className="event-list">
            {visibleEvents.slice().reverse().slice(0, 12).map(event => <EventRow key={event.eventId} event={event} />)}
            {!visibleEvents.length && <div className="empty">No {activeFeature === "usb-storage" ? "USB storage" : activeFeature === "web-upload" ? "browser upload" : activeFeature === "nearby-transfer" ? "nearby transfer" : activeFeature === "clipboard" ? "clipboard" : "application execution"} events recorded yet.</div>}
          </div>
        </section>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
