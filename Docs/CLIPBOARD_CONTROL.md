# Velox Mac DLP — Clipboard Control Architecture & Enforcement

## Overview

**Clipboard Control** prevents unauthorized data exfiltration via the macOS system pasteboard (`NSPasteboard.general`). It provides two enforceable security policies:
1. **Block All Clipboard**: Immediately clears any new content copied to the system pasteboard from any application on the Mac.
2. **Block Copy From Selected Applications**: Identifies the foreground source application by its signed code identity (Team ID, bundle ID / signing identifier, platform binary status), and clears newly copied content if the application matches a blocked rule in policy.

---

## Technical Architecture & Boundary Separation

### 1. The macOS Platform Limitation
* **No Kernel Clipboard Event**: Apple's `EndpointSecurity` framework does **not** provide clipboard authorization events (`AUTH_COPY` or `AUTH_PASTE` do not exist in macOS).
* **Agent-Level Observation**: Clipboard Control is enforced by the logged-in user agent process (`VeloxMacDLP.app`) running in the user's GUI session.
* **Privileged Logging & Policy Storage**: The root Endpoint Security system extension (`VeloxExtension`) maintains authoritative policy persistence, snapshot distribution, and writes to `/Library/Logs/VeloxMacDLP/events.jsonl`.

### 2. Detection & Immediate Content Neutralization
* The user agent continuously monitors `NSPasteboard.general.changeCount`.
* When a change occurs:
  1. The agent inspects `NSWorkspace.shared.frontmostApplication`.
  2. The agent queries macOS Security Framework (`SecCodeCopyGuestWithAttributes`, `SecCodeCopyStaticCode`, `SecCodeCopySigningInformation`) to extract cryptographically verified code signing metadata.
  3. The `PolicyEngine` evaluates whether copying is allowed.
  4. If blocked, `pasteboard.clearContents()` is executed immediately—wiping the content before other processes can paste it.
  5. An audit event (`module: "clipboard-control", action: "copy", decision: "blocked"`) is dispatched to the privileged daemon via XPC.
  6. A native macOS notification banner is dispatched to inform the user that copying was blocked.

### 3. Coverage Across Copy Vectors
Because `NSPasteboard` changes occur regardless of how the copy operation was triggered, enforcement covers:
- Keyboard shortcuts (`⌘C`, `⌃C`)
- Application menu commands (`Edit > Copy`)
- Contextual menus (Right click -> Copy)
- Drag-and-drop actions that write items to the pasteboard

---

## Policy Configuration Schema

```json
{
  "clipboardControl": {
    "mode": "block-selected-apps",
    "blockedApplications": [
      {
        "ruleId": "block-terminal-copy",
        "signingId": "com.apple.Terminal"
      }
    ]
  }
}
```

---

## Privacy-Safe Telemetry

Velox DLP strictly preserves user privacy:
- Copied text, images, or payload contents are **never** inspected, captured, or logged.
- The audit record contains only coarse metadata:
  - `sourceApplication`: Process name and bundle ID
  - `signingId`: Cryptographic signing identifier
  - `contentTypes`: Generic type tags (e.g. `["text"]`, `["image"]`, `["file-url"]`)
  - `itemCount`: Number of items copied
  - `decision`: `"blocked"` or `"allowed"`
