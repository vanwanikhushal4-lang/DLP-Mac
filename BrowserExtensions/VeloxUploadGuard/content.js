(() => {
  "use strict";

  const runtimeAPI = globalThis.browser ?? globalThis.chrome;
  let policyMode = "enforce"; // Fail closed until the signed native policy responds.
  let protectedDirectoryNames = [];

  function sendMessage(message) {
    if (globalThis.browser?.runtime?.sendMessage) {
      return globalThis.browser.runtime.sendMessage(message);
    }
    return new Promise((resolve) => runtimeAPI.runtime.sendMessage(message, resolve));
  }

  async function refreshPolicy() {
    try {
      const response = await sendMessage({ type: "getVeloxPolicy" });
      if (response?.ok && ["disabled", "audit-only", "enforce"].includes(response.mode)) {
        policyMode = response.mode;
        protectedDirectoryNames = Array.isArray(response.protectedDirectoryNames)
          ? response.protectedDirectoryNames
          : [];
      }
    } catch (_) {
      // Preserve the last trustworthy mode. The initial value intentionally fails closed.
    }
  }

  function report(fileNames, interaction, blocked) {
    sendMessage({
      type: "recordUploadAttempt",
      fileNames,
      interaction,
      blocked
    }).catch(() => {});
  }

  function showBlockedNotice(fileNames) {
    const existing = document.getElementById("velox-dlp-upload-blocked-notice");
    existing?.remove();

    const notice = document.createElement("div");
    notice.id = "velox-dlp-upload-blocked-notice";
    notice.setAttribute("role", "alert");
    notice.style.cssText = [
      "position:fixed",
      "z-index:2147483647",
      "right:24px",
      "top:24px",
      "max-width:380px",
      "padding:16px 18px",
      "border-radius:12px",
      "background:#13161c",
      "color:#fff",
      "border:1px solid #ff4d5e",
      "box-shadow:0 12px 40px rgba(0,0,0,.38)",
      "font:600 14px/1.45 -apple-system,BlinkMacSystemFont,sans-serif",
      "letter-spacing:.01em"
    ].join(";");

    const detail = fileNames.length === 1 ? ` (${fileNames[0]})` : "";
    notice.textContent = `Upload blocked by Velox DLP${detail}`;
    (document.documentElement || document.body)?.appendChild(notice);
    globalThis.setTimeout(() => notice.remove(), 6000);
  }

  function extractFilesFromDataTransfer(dt) {
    if (!dt) return [];
    const names = [];
    if (dt.files && dt.files.length > 0) {
      for (let i = 0; i < dt.files.length; i++) {
        const file = dt.files[i];
        if (file && file.name) names.push(file.name);
        else if (file && file.type) names.push(file.type);
      }
    }
    if (dt.items && dt.items.length > 0) {
      for (let i = 0; i < dt.items.length; i++) {
        const item = dt.items[i];
        if (item.kind === "file") {
          try {
            const file = item.getAsFile?.();
            if (file && file.name && !names.includes(file.name)) {
              names.push(file.name);
            } else if (file && file.type && !names.includes(file.type)) {
              names.push(file.type);
            } else if (names.length === 0) {
              names.push(item.type || "pasted-file");
            }
          } catch (_) {
            if (names.length === 0) names.push("file");
          }
        } else if (item.type.startsWith("image/") && names.length === 0) {
          names.push(item.type);
        }
      }
    }
    return names;
  }

  function handleAttempt(event, fileNames, interaction, clearSelection) {
    if (fileNames.length === 0 || policyMode === "disabled") return;

    const blocked = policyMode === "enforce";
    report(fileNames, interaction, blocked);
    if (!blocked) return;

    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();
    clearSelection?.();
    showBlockedNotice(fileNames);
  }

  // Intercept file chooser clicks before macOS file dialog opens
  globalThis.addEventListener("click", (event) => {
    const target = event.target;
    if (target instanceof HTMLInputElement && target.type.toLowerCase() === "file" && policyMode === "enforce") {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      report(["file-picker-dialog"], "file-picker-click", true);
      showBlockedNotice(["File uploads"]);
    }
  }, true);

  // Intercept file picker changes
  globalThis.addEventListener("change", (event) => {
    const input = event.target;
    if (!(input instanceof HTMLInputElement) || input.type.toLowerCase() !== "file") return;
    const fileNames = Array.from(input.files ?? [], (file) => file.name || file.type || "file");
    handleAttempt(event, fileNames, "file-picker", () => {
      try { input.value = ""; } catch (_) {}
    });
  }, true);

  // Intercept drag-and-drop file uploads
  globalThis.addEventListener("dragover", (event) => {
    if (policyMode === "enforce" && event.dataTransfer?.types?.includes("Files")) {
      event.dataTransfer.dropEffect = "none";
    }
  }, true);

  globalThis.addEventListener("drop", (event) => {
    let fileNames = extractFilesFromDataTransfer(event.dataTransfer);
    if (fileNames.length === 0 && event.dataTransfer?.types?.includes("Files")) {
      fileNames = ["dragged-file"];
    }
    handleAttempt(event, fileNames, "drag-drop");
  }, true);

  // Intercept pasted files and clipboard screenshots
  globalThis.addEventListener("paste", (event) => {
    let fileNames = extractFilesFromDataTransfer(event.clipboardData);
    if (fileNames.length === 0 && event.clipboardData?.types?.includes("Files")) {
      fileNames = ["pasted-image"];
    }
    handleAttempt(event, fileNames, "paste");
  }, true);

  globalThis.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    const inputs = Array.from(form.querySelectorAll('input[type="file"]'));
    const fileNames = inputs.flatMap((input) => Array.from(input.files ?? [], (file) => file.name));
    handleAttempt(event, fileNames, "form-submit", () => {
      inputs.forEach((input) => { try { input.value = ""; } catch (_) {} });
    });
  }, true);

  try {
    console.log("[Velox DLP Upload Guard] Active on", globalThis.location?.host || "page");
  } catch (_) {}

  refreshPolicy();
  globalThis.setInterval(refreshPolicy, 2000);
})();
