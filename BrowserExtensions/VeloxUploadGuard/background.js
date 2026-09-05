const runtimeAPI = globalThis.browser ?? globalThis.chrome;

function sendNative(message) {
  if (globalThis.browser?.runtime?.sendNativeMessage) {
    return globalThis.browser.runtime.sendNativeMessage("co.velox.macdlp", message);
  }

  return new Promise((resolve) => {
    runtimeAPI.runtime.sendNativeMessage("co.velox.macdlp", message, (response) => {
      const error = runtimeAPI.runtime.lastError;
      resolve(error ? { ok: false, message: error.message } : response);
    });
  });
}

runtimeAPI.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || (message.type !== "getVeloxPolicy" && message.type !== "recordUploadAttempt")) {
    return false;
  }

  const nativeMessage = message.type === "getVeloxPolicy"
    ? { action: "getWebUploadPolicy" }
    : {
        action: "recordBrowserUploadAttempt",
        pageURL: sender?.url ?? "",
        fileNames: Array.isArray(message.fileNames) ? message.fileNames : [],
        interaction: message.interaction ?? "unknown",
        blocked: Boolean(message.blocked)
      };

  sendNative(nativeMessage)
    .then((response) => sendResponse(response ?? { ok: false, message: "No native response." }))
    .catch((error) => sendResponse({ ok: false, message: String(error) }));
  return true;
});
