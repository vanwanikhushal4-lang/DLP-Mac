# WhatsApp Transfer Control

Velox routes outbound file reads from WhatsApp Web and the signed WhatsApp Mac
application through the existing Web Upload Control and Classified Egress
Control. Incoming messages, received media, and downloads remain allowed because
the Endpoint Security rule requires read-only access to an existing local file.

## Trusted identities

The native-client policy uses code-signing identity and Team ID together:

| Component | Signing ID | Team ID |
| --- | --- | --- |
| WhatsApp for Mac | `net.whatsapp.WhatsApp` | `57T9237FN3` |
| Intents extension | `net.whatsapp.WhatsApp.Intents` | `57T9237FN3` |
| Notification service extension | `net.whatsapp.WhatsApp.ServiceExtension` | `57T9237FN3` |

A copied or renamed application retains its signing identity. A lookalike binary
with the same claimed identifier but a different Team ID does not match.

## Enforced paths

- WhatsApp Web in Safari, Chrome, Edge, Firefox, Brave, Opera, and Arc.
- Browser-installed WhatsApp PWAs whose process retains a supported browser or
  WebKit identity.
- WhatsApp for Mac attachment picker and drag/drop when the app reads a regular
  file from a configured protected user folder.
- Finder **Open With WhatsApp** and WhatsApp document-handler routes, because
  they resolve to the same signed main application reading the selected file.
- Copied-file paste into a supported browser or WhatsApp for Mac through the
  user-session pasteboard guard, followed by Endpoint Security authorization if
  the destination opens the file path.

With `webUploadControl.mode = enforce`, every matching read is denied. With
`ocrControl.egressMode = enforce` and the `web-upload` channel selected, an
unknown file is held, classified asynchronously on device, and then allowed on
retry only when its fresh metadata-bound verdict is clean.

For the native Mac app, Velox also keeps Network Filter data callbacks active
for the exact configured WhatsApp identities. A successful Endpoint Security
deny creates a metadata-only outbound hold before asynchronous OCR:

- pending OCR: current WhatsApp outbound data is dropped;
- clean result: the hold is released and the user can retry;
- protected result: Velox quarantines any exact hash-matched broker-staged copy,
  verifies the live WhatsApp process by signing ID and Team ID, terminates that
  client session, and reduces the network hold to a five-second shutdown tail.
  The user's original file is never moved or deleted.

This closes the document-picker staging gap where WhatsApp can receive bytes
from an Apple broker before its later attributable file open. The hold file is
root-only and contains no file content or recognized text.

## Honest boundary

Endpoint Security exposes the process and file read, not the WhatsApp recipient,
conversation, Send button, or encrypted message body. Therefore Velox treats a
matching WhatsApp read of a protected local file as an outbound transfer
candidate. This can also match a local preview opened by WhatsApp.

The current control does not claim coverage for typed message text, raw image
bytes pasted without a file URL, camera/microphone capture, forwarding content
already inside WhatsApp, files outside configured folders, or an upload path
that never produces an attributable file read. During a native-app hold, the
public Network Extension API cannot distinguish attachment bytes from another
encrypted WhatsApp message, so other outbound WhatsApp traffic can be
interrupted while classification is pending. A protected result closes the
WhatsApp client session because public APIs provide no per-attachment cancel
primitive; the user must reopen WhatsApp. If staging cleanup or signed-process
verification fails, the original bounded fail-closed hold is retained. Those paths require separate
clipboard, capture, application, or protocol-specific controls.

The scanned WhatsApp build registers URL schemes but contains no Share
extension; its only app extensions are Intents and notification service. URL
schemes that merely open a chat contain no local file bytes to authorize. If a
future WhatsApp update adds a new file-reading helper or Share extension, its
signed identity must be acceptance-tested and added to `nativeUploadClients`.

## Manual acceptance test

Use the signed installed build with the Endpoint Security extension activated.

1. Enable Web & App Upload Control in **Enforce** mode. From WhatsApp for Mac,
   attach a uniquely named file from Documents. The attachment must fail, a
   **Blocked by Velox DLP** notification must name WhatsApp, and Live activity
   must show `native-app-file-open` with signing ID `net.whatsapp.WhatsApp`.
2. Repeat by dragging the file into a conversation and by copying/pasting the
   file from Finder. Each route must be blocked.
3. Repeat through WhatsApp Web in Safari and Chrome. The events must use the
   browser identity and remain in module `web-upload-control`.
4. Set route-wide Web & App Upload Control to **Disabled**, enable Classified
   Egress in **Enforce**, and keep `web-upload` selected. Attempt a never-scanned
   Aadhaar/PAN/card/confidential test image. The first read must create a
   pending native-app network hold; the send must fail, and after OCR the
   activity log must show one `native-app-network-drop` plus the classification.
   WhatsApp must close, and reopening it after five seconds must not remain
   app-wide blocked. The original source file must remain in place.
5. Repeat step 4 with a clean supported image/PDF. The first read is held; the
   first send may fail while OCR runs, and a retry must be allowed after the
   clean verdict releases the hold.
6. Receive/download a uniquely named media file in WhatsApp. The write must
   succeed and must not create a blocked outbound-upload event.
7. Change a previously clean file and retry. Its stale cached verdict must not be
   reused; the changed file must be held for fresh classification.
8. Immediately after step 4, reopen WhatsApp and attach a clean image. It must
   be allowed; the earlier protected file must not leave a stale app-wide hold.
