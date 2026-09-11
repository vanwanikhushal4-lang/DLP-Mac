# OCR Content Classification

## Goal

Velox classifies text present in images, screenshots, and scanned PDFs without sending the document or recognized text off the Mac. It provides a local classification primitive that later DLP egress controls can call before allowing an upload, removable-media copy, print, or nearby transfer.

## Implemented prototype

- Apple Vision accurate text recognition for image formats supported by ImageIO.
- PDFKit embedded-text extraction, with Vision OCR fallback for image-only pages.
- Configurable recognition languages, confidence threshold, file-size limit, and PDF page limit.
- Keyword, regular-expression, Luhn-valid payment-card, Indian PAN, and Verhoeff-valid Aadhaar classification rules.
- `enforce`, `audit-only`, and `disabled` policy modes for manual/document OCR.
- A separate screenshot mode. Endpoint Security attributes file creation to Apple's signed screenshot tools; the user-session host waits for the file to stabilize, classifies it, and quarantines or deletes it when policy requires enforcement.
- A React console panel for policy modes, current rule/language status, local test scans, classification summaries, and activity events.
- Native “Blocked by Velox DLP” notifications for enforced classifications.

## Security and privacy contract

OCR runs on device and outside Endpoint Security authorization callbacks. Recognized text and image bytes remain in memory. The activity log stores only privacy-safe metadata: a 12-character SHA-256 prefix, uniform type identifier, source category, rule IDs, classification names, character/page counts, confidence, duration, and remediation outcome. It does not store filenames, full paths, extracted text, or thumbnails.

Only events whose rule IDs and classification names agree with the active extension-owned policy are accepted over XPC. Policies reject unknown properties, duplicate rule IDs, invalid regular expressions, oversized settings, and malformed language identifiers.

## macOS boundary

The screenshot path is detect-and-remediate, not pre-capture blocking. macOS creates the screenshot before Vision can classify it. Quarantine is therefore the safe default; deletion is available only as an explicit policy choice. Screenshots created by third-party capture applications need separate per-application discovery or ScreenCaptureKit/MDM strategy and are not claimed as covered here.

The local test picker proves OCR and policy evaluation but does not by itself make every DLP channel content-aware. Production egress controls should invoke the shared classification service before their own decision point and use a bounded cache keyed by content hash and policy version.

## Manual acceptance test

1. Open **OCR Classification** in the Velox console and set document OCR to **Enforce**.
2. Choose an image containing the words `CONFIDENTIAL` or a synthetic Luhn-valid test card number such as `4111 1111 1111 1111`.
3. Confirm the result is **blocked**, a classification chip is shown, and no recognized text appears in `/Library/Logs/VeloxMacDLP/events.jsonl`.
4. Scan a clean image and confirm the result is **allowed**.
5. Set screenshot OCR to **Audit only**, capture the same test content with Apple's screenshot tool, and confirm a `would-block` event while the screenshot remains.
6. Set screenshot OCR to **Enforce**, repeat the capture, and confirm the screenshot is moved to `~/Library/Application Support/VeloxMacDLP/Quarantine/Screenshots/` and the native notification appears.
7. Test a text PDF and a scanned PDF. Confirm the UI reports embedded PDF text for the former and Apple Vision OCR for the latter.

Use only synthetic identifiers in tests. Never test with a real payment-card, PAN, or Aadhaar number.
