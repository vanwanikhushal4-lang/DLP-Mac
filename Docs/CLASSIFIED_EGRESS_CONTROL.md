# Classified Egress Control

## Contract

Velox applies the four current on-device classifications—Payment Card Data,
Indian Tax Identifier, Indian Identity Data, and Confidential Document—to
supported outbound file-transfer paths. No recognized text or file bytes are
written to telemetry.

The policy lives under `ocrControl`:

- `egressMode`: `enforce`, `audit-only`, or `disabled`.
- `protectedEgressChannels`: `usb`, `web-upload`, `email`, and/or
  `nearby-transfer`.
- `protectedEgressClassifications`: an empty array means every active OCR
  classification; otherwise only the listed active classifications are denied.

## Decision flow

1. Endpoint Security identifies an outbound file candidate without reading its
   contents.
2. A constant-time cache lookup checks the exact path, size, nanosecond mtime,
   and policy version.
3. In enforce mode, an unknown or stale file is denied with
   `content-egress-classification-required`.
4. The logged-in host sees that event, runs Apple Vision/PDFKit/plain-text
   extraction asynchronously, and sends only the metadata-bound verdict to the
   authenticated extension.
5. On retry, a clean file is allowed and a file matching a protected
   classification is denied with a channel-specific rule ID.

Changing either the file metadata or policy version invalidates the verdict.
OCR never runs inside the kernel authorization deadline.

## Current channel boundaries

| Channel | Endpoint signal | Current boundary |
| --- | --- | --- |
| Browser upload | Read-only `AUTH_OPEN` by a supported browser in protected user folders | Downloads use write/finalization paths and remain allowed. A browser reading a local file for a non-upload purpose can look identical at this layer; the Safari picker guard remains complementary. |
| Native email | Read-only `AUTH_OPEN` by a configured signed Mail/Outlook client | Controls attachment-file access; macOS does not expose recipient or Send-button authorization. |
| AirDrop/Bluetooth | Read-only `AUTH_OPEN` by known Apple sharing/Bluetooth services | Incoming writes remain allowed. `sharingd` is honestly attributed as Apple nearby sharing because it serves multiple Share Sheet routes. |
| USB | `AUTH_COPYFILE` with an external physical-volume destination | Covers copy operations that produce this explicit source/destination event. Streaming copy implementations must be acceptance-tested and need additional stateful correlation if they do not emit `AUTH_COPYFILE`. |

## Manual acceptance matrix

Run each row with one clean file and one file matching each of the four rules.
The first attempt for a previously unseen file must be held; after the
classification event appears, retry it.

| Route | Expected clean result | Expected classified result |
| --- | --- | --- |
| Safari/Chrome file upload | Allowed on retry | Blocked with classification notification |
| Apple Mail/Outlook attachment | Allowed on retry | Blocked with classification notification |
| AirDrop/Apple Share/Bluetooth File Exchange | Allowed on retry | Blocked with classification notification |
| Finder copy to physical USB volume | Allowed on retry | Blocked with classification notification |

Also verify browser downloads and incoming AirDrop/Bluetooth transfers remain
uninterrupted, a modified file is held again, unsupported files stay held in
enforce mode, and no extracted identifiers appear in `events.jsonl`.
