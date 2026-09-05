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

function EventRow({ event }) {
  const isUploadEvent = event.module === "web-upload-control";
  const appName = isUploadEvent
    ? event.resourcePath?.split("/").pop() || "Protected file"
    : event.executablePath?.split("/").pop() || event.signingId || "Unknown";
  const detail = isUploadEvent
    ? `${event.signingId || "Browser"} · ${event.resourcePath || "Unknown file"}`
    : event.signingId || event.executablePath;
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
  const [busyApp, setBusyApp] = useState(null);
  const [busyMode, setBusyMode] = useState(false);
  const [busyWebUpload, setBusyWebUpload] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

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
  const filteredApps = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return apps;
    return apps.filter(app => `${app.name} ${app.signingId} ${app.bundleIdentifier}`.toLowerCase().includes(needle));
  }, [apps, query]);

  const isBlocked = app => (app.signingId && blockedSigningIds.has(app.signingId.toLowerCase())) || blockedPaths.has(app.executablePath);

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

  async function openSafariSettings() {
    try {
      const resp = await nativeCall("openSafariExtensionSettings");
      setNotice(resp?.message || "In Safari: Ensure Develop > 'Allow Unsigned Extensions' is enabled, then turn on Velox DLP Upload Guard in Settings > Extensions.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to open Safari settings.");
    }
  }

  const online = snapshot?.extensionStatus === "enforcing";
  const mode = snapshot?.mode || "audit-only";
  const webUploadMode = snapshot?.webUploadMode || "disabled";
  const blockedCount = snapshot?.blockedRuleCount || 0;
  const protectedFolders = snapshot?.webUploadProtectedDirectories || [];
  const visibleEvents = events.filter(event => activeFeature === "web-upload"
    ? event.module === "web-upload-control"
    : event.module !== "web-upload-control");
  const recentUploadBlocks = events.filter(event => event.module === "web-upload-control" && event.decision === "blocked").length;
  const safariGuardVerified = events.some(event => event.action === "browser-upload-attempt" && event.decision === "blocked");
  const isWebUploadView = activeFeature === "web-upload";

  return (
    <div className="shell">
      <aside>
        <div className="brand"><ShieldMark /><div><strong>Velox</strong><span>Mac DLP</span></div></div>
        <nav>
          <button disabled><span>⌂</span>Overview</button>
          <button className={!isWebUploadView ? "active" : ""} onClick={() => setActiveFeature("applications")}><span>▦</span>Application Control</button>
          <button className={isWebUploadView ? "active" : ""} onClick={() => setActiveFeature("web-upload")}><span>⇧</span>Web Upload Control</button>
          <button disabled><span>≋</span>Activity</button>
          <button disabled><span>⚙</span>Agent Settings</button>
        </nav>
        <div className="sidebar-status"><StatusPill online={online} /><span>Agent 1.2.4</span></div>
      </aside>

      <main>
        <header>
          <div>
            <p className="eyebrow">ENDPOINT / THIS MAC</p>
            <h1>{isWebUploadView ? "Web Upload Control" : "Application Control"}</h1>
            <p>{isWebUploadView ? "Prevent protected files from leaving this Mac through supported browsers." : "Control which applications can run on this endpoint."}</p>
          </div>
          <StatusPill online={online} />
        </header>

        {error && <div className="banner error"><strong>Control service unavailable</strong><span>{error}</span></div>}
        {notice && <div className="banner success"><strong>Policy activated</strong><span>{notice}</span></div>}

        {!isWebUploadView ? <>
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
        </> : <>
          <section className="summary-grid">
            <article><span className="card-label">UPLOAD PROTECTION</span><strong>{modeCopy[webUploadMode]?.label}</strong><p>Downloads and normal browser traffic remain allowed.</p></article>
            <article><span className="card-label">RECENTLY BLOCKED</span><strong>{recentUploadBlocks}</strong><p>Upload candidates in the current activity window.</p></article>
            <article><span className="card-label">SAFARI GUARD</span><strong className={safariGuardVerified ? "state-enabled" : "state-action"}>{safariGuardVerified ? "Verified" : "Action required"}</strong><p>{safariGuardVerified ? "A real browser-boundary block was recorded." : "One-time Safari approval is required."}</p></article>
          </section>

          <section className="panel upload-panel">
            <div className="upload-heading">
              <div className="upload-icon">⇧</div>
              <div>
                <div className="title-with-badge"><h2>Browser upload protection</h2><span>PROTOTYPE</span></div>
                <p>Stops file-picker, drag/drop and pasted-file uploads before Safari gives them to a website. Incoming downloads remain allowed.</p>
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

          {!safariGuardVerified && <section className="panel safari-setup-panel">
            <div><span className="coverage-state warning">ONE-TIME SETUP</span><h2>Enable Velox DLP Upload Guard in Safari</h2><p>Open Safari settings, enable the extension, and grant access to all websites.</p></div>
            <button className="setup-button" onClick={openSafariSettings}>Open Safari Settings</button>
          </section>}

          <section className="panel coverage-panel">
            <div><span className="coverage-state">SAFARI PROTOTYPE</span><h2>Browser-boundary protection + Endpoint Security telemetry</h2><p>Safari uploads are stopped at the page boundary. Endpoint Security continues to audit protected-folder access. Chromium and Firefox require their corresponding managed browser extension before they can be claimed as enforced.</p></div>
          </section>
        </>}

        <section className="panel activity-panel">
          <div className="panel-heading"><div><h2>Live activity</h2><p>{isWebUploadView ? "Latest browser file-transfer decisions from Endpoint Security" : "Latest application execution decisions from Endpoint Security"}</p></div><button className="refresh" onClick={refreshEvents}>Refresh</button></div>
          <div className="event-list">
            {visibleEvents.slice().reverse().slice(0, 12).map(event => <EventRow key={event.eventId} event={event} />)}
            {!visibleEvents.length && <div className="empty">No {isWebUploadView ? "browser upload" : "application execution"} events recorded yet.</div>}
          </div>
        </section>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
