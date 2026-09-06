# Clipboard Control

## Prototype contract

Clipboard Control monitors the logged-in user's general macOS pasteboard and removes newly copied content when policy requires it. It supports two blocking scopes:

- `block-all`: clear every new clipboard item regardless of the source application.
- `block-selected-apps`: clear new items only when the foreground source process matches a configured signed application rule.

`disabled` stops normal clipboard monitoring and blocking. Application selections are retained so an administrator can switch modes without rebuilding the list.

The source application is represented by code-signing ID and exact executable path. Display names are used only in the console and notifications.

## Data handling

Velox never records the copied payload. Clipboard events contain only:

- source application name and signed process identity;
- coarse categories such as text, formatted text, image, files, or application data;
- pasteboard item count;
- policy decision and matching rule ID.

Copied text, image bytes, file paths, and arbitrary pasteboard values are not sent through XPC or written to the activity log.

## Enforcement flow

1. The host app polls `NSPasteboard.general.changeCount` every 100 milliseconds.
2. On a change, it captures the foreground process and inspects its live code signature.
3. The local `PolicyEngine` evaluates `clipboardControl`.
4. A blocking decision calls `clearContents()` immediately and posts **Blocked by Velox DLP**.
5. Privacy-safe event metadata is sent through authenticated XPC to the system extension, which reevaluates the authoritative policy and writes the structured event.

The existing copied-file browser-upload guard remains separate. A clipboard item cleared by Clipboard Control cannot continue to browser-upload evaluation.

## Manual acceptance test

Use a signed build with the host app running and the system extension active.

### Block all

1. Open VeloxMacDLP, choose **Clipboard Control**, then **Block all**.
2. Copy plain text from TextEdit or Notes and immediately paste into a second app. The original data must not paste.
3. Repeat with rich text, an image, and a Finder file copy.
4. Confirm a **Blocked by Velox DLP** notification appears and Live activity identifies the source app and coarse content type without showing the copied data.

### Selected apps

1. Choose **Selected apps**, select TextEdit, and leave Notes unselected.
2. Copy unique text from TextEdit and paste into Notes. It must be cleared and logged as blocked.
3. Copy unique text from Notes and paste into TextEdit. It must remain available and be logged as allowed.
4. Toggle TextEdit off and confirm copying from it works again.
5. Quit the Velox host and confirm Clipboard Control no longer enforces; this demonstrates why production deployment must keep the per-user host alive with managed launch-at-login.

### Race and path coverage

Repeat both modes using Command-C, the Edit menu, context menus, Finder file copy, screenshots copied to the clipboard, and a rapid copy-then-paste sequence. Exercise clipboard-manager software separately because background writers cannot always be attributed to the foreground app.

Inspect evidence with:

```sh
tail -f "/Library/Logs/VeloxMacDLP/events.jsonl"
```

## macOS boundary

Endpoint Security has no clipboard authorization event, and `NSPasteboard` has no public pre-copy denial callback. The prototype therefore performs rapid post-copy clearing rather than a kernel preflight denial. A paste attempted inside the polling interval can race enforcement, and background clipboard writers can be attributed to the foreground process.

Do not describe this prototype as zero-race prevention. Production hardening requires a managed, non-user-quittable per-user agent, watchdog/launch-at-login behavior, latency telemetry, stress testing, and documented handling for clipboard managers and remote-session tools.
