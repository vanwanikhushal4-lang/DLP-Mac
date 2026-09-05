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

  function handleAttempt(event, fileNames, interaction, clearSelection) {
    if (fileNames.length === 0 || policyMode === "disabled") return;

    const blocked = policyMode === "enforce";
    report(fileNames, interaction, blocked);
    if (!blocked) return;

    event.preventDefault();
    event.stopImmediatePropagation();
    clearSelection?.();
    showBlockedNotice(fileNames);
  }

  globalThis.addEventListener("change", (event) => {
    const input = event.target;
    if (!(input instanceof HTMLInputElement) || input.type.toLowerCase() !== "file") return;
    const fileNames = Array.from(input.files ?? [], (file) => file.name);
    handleAttempt(event, fileNames, "file-picker", () => { input.value = ""; });
  }, true);

  globalThis.addEventListener("drop", (event) => {
    const fileNames = Array.from(event.dataTransfer?.files ?? [], (file) => file.name);
    handleAttempt(event, fileNames, "drag-drop");
  }, true);

  globalThis.addEventListener("paste", (event) => {
    const fileNames = Array.from(event.clipboardData?.files ?? [], (file) => file.name);
    handleAttempt(event, fileNames, "paste");
  }, true);

  globalThis.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    const inputs = Array.from(form.querySelectorAll('input[type="file"]'));
    const fileNames = inputs.flatMap((input) => Array.from(input.files ?? [], (file) => file.name));
    handleAttempt(event, fileNames, "form-submit", () => {
      inputs.forEach((input) => { input.value = ""; });
    });
  }, true);

  refreshPolicy();
  globalThis.setInterval(refreshPolicy, 2000);
})();
