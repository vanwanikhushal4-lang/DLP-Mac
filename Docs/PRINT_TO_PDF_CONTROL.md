# Print-to-PDF / File Control

## Contract

This control protects PDF file output as a local egress route. Its policy is independent from physical CUPS printer control:

- `enforce`: deny matching new PDF file creates;
- `audit-only`: allow the create and record `would-block`;
- `disabled`: do not inspect PDF creates for this feature.

`blockSaveAsPDF` is retained as the backend policy switch. The default is `true`.

## Enforcement

The Endpoint Security extension handles `ES_EVENT_TYPE_AUTH_CREATE` before a new file exists. A request is a candidate only when all of these are true:

1. the destination extension is `.pdf` (case-insensitive);
2. it is inside Desktop, Documents, Downloads, Movies, Music, Pictures, or Public under a user home;
3. the source process is identified and is not critical macOS infrastructure or an authentic Velox component.

Enforce mode answers the authorization event with deny, records a `print-to-pdf-control` / `pdf-file-create` event, and posts **Blocked by Velox DLP**. No PDF content is read or logged.

## Platform boundary

macOS Endpoint Security reports the file operation and actor, not the UI command that caused it. The same authorization covers Save as PDF and equivalent application export workflows. For this reason, product copy and telemetry say **PDF file output**, not that the exact Print dialog button was observed.

Browser Print-to-PDF output is not exempted. Normal downloads use staging names such as `.crdownload`, `.download`, `.part`, or `.partial`, then finalize through a rename; those paths do not match this `.pdf` create authorization. The current implementation protects direct new-file creation. Applications that overwrite an existing PDF, direct-to-final browser downloads, or workflows that finalize a temporary file through an atomic rename need separate acceptance coverage and must not be represented as covered until those event paths are implemented and verified.

## Manual acceptance test

1. Open **Printer Control** in Velox and set **Print-to-PDF / File Control** to **Enforce**.
2. In TextEdit or Microsoft Word, choose Print, then Save as PDF to Documents. Confirm creation fails, a native notification appears, and Live activity shows a blocked PDF output event.
3. Switch to **Audit only**, repeat, and confirm the PDF is created while Live activity records `would-block`.
4. Switch to **Disabled** and confirm normal PDF creation succeeds.
5. Return to **Enforce**, use Print → Save as PDF from each supported browser and confirm direct PDF output is denied.
6. Download an existing PDF in Safari, Chrome, Edge, Firefox, Brave, Opera, and Arc as applicable. Confirm each staged download succeeds.
7. Confirm non-PDF file creation and critical Velox/macOS processes are unaffected.
