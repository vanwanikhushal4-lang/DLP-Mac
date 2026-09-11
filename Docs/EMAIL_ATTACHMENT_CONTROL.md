# Email Attachment Control

## Contract

Velox blocks a securely identified native mail client from reading a file whose current size and nanosecond modification time match an Endpoint Data Discovery classification record. The first supported clients are Apple Mail (`com.apple.mail`, Apple platform binary) and Microsoft Outlook (`com.microsoft.Outlook`, Team ID `UBF8T346G9`).

The control supports `enforce`, `audit-only`, and `disabled`. `protectedClassifications` may select active OCR classifications; an empty list protects every active classification.

## Enforcement flow

1. Endpoint Data Discovery extracts and classifies supported local content asynchronously.
2. It reports only file metadata, classification labels, rule IDs, and a 12-character hash prefix to the privileged extension. Extracted text is never sent or logged.
3. The extension caches that record in memory, bound to absolute path, size, and modification time.
4. On `AUTH_OPEN`, a read-only open by a configured signed mail client is checked against the cache.
5. Enforce mode returns zero allowed flags before the client can read the classified bytes; audit-only allows and logs `would-block`.
6. A successful denial creates a structured `email-attachment-control` event and a native “Blocked by Velox DLP” notification.

Write and read/write opens remain allowed, preserving downloads and ordinary message synchronization. Modified or unscanned files fail open until a later discovery scan classifies the current bytes.

## Platform boundary

Endpoint Security does not expose a reliable compose/send event, recipient, subject, or final attachment list. This module is therefore pre-egress file-access enforcement, not message-level inspection. Webmail is covered by Web Upload Control. Recipient-aware, domain-aware, and body-aware email DLP requires mail-gateway/API integration.

## Manual acceptance

1. Enable OCR and Endpoint Data Discovery, run a scan, and confirm the target file is listed as a finding.
2. Set Email Attachment Control to Audit only. Attach the classified file in Apple Mail and verify a `would-block` event while the file remains attachable.
3. Set the mode to Enforce and repeat. Verify the read is denied and the notification names the file, mail client, and classification.
4. Download an attachment and confirm the write succeeds.
5. Edit the classified file and retry before rescanning. Confirm it is not blocked; run discovery again and confirm enforcement resumes if it still classifies.
6. Confirm an unclassified file attaches normally.
