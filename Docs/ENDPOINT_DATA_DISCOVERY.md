# Endpoint Data Discovery

## Contract

Endpoint Data Discovery performs bounded, scheduled or on-demand scans of:

- the current user's local home directory;
- mounted external/local volumes; and
- mounted network shares such as SMB or AFP volumes.

Supported content is classified locally using the existing Velox rules. The first implementation handles plain-text files, images through Apple Vision, PDFs through PDFKit, and scanned PDF pages through Vision. Extracted content remains memory-only.

## Modes

- `disabled`: no automatic or manual scans run.
- `audit-only`: matched files are reported but never modified.
- `enforce`: matched files are reported and, when enabled, tagged with the `com.velox.macdlp.classification` extended attribute.

Tag failures never hide a finding. Read-only volumes and filesystems without xattr support remain report-only and increment the report's tag-failure count.

## Policy

```json
{
  "endpointDiscoveryControl": {
    "mode": "audit-only",
    "scheduleIntervalMinutes": 1440,
    "includeLocalHome": true,
    "includeMountedVolumes": true,
    "includeMountedShares": true,
    "tagClassifiedFiles": true,
    "maxFilesPerScan": 10000
  }
}
```

The schedule interval is bounded to 15 minutes through 7 days. A scan inspects at most 100,000 regular files and skips hidden files, package descendants, symlinks, caches, build folders, and the Velox report directory.

## Reports and telemetry

Complete reports are written with user-only permissions to:

`~/Library/Application Support/VeloxMacDLP/Discovery/Reports/`

Each report includes paths, a 12-character content-hash prefix, matched rule IDs, classification names, location kind, tag outcome, counters, and timing. It never includes extracted text, image bytes, or document contents. The console receives at most the first 100 findings; the complete JSON remains on disk.

The authenticated host forwards validated finding and scan-summary events to the Endpoint Security extension, which remains the structured event-log owner.

## macOS permission boundary

The host process requires Full Disk Access for complete coverage of Desktop, Documents, Downloads, Mail data, and other privacy-protected locations. macOS does not allow an application to grant itself this permission. Network shares must be mounted and authenticated in the user's session when the scan starts.

## Manual acceptance test

1. Grant `/Applications/VeloxMacDLP.app` Full Disk Access.
2. Create a UTF-8 text file in Documents containing `CONFIDENTIAL` and the Luhn-valid test number `4111 1111 1111 1111`.
3. Open **Endpoint Data Discovery**, select **Audit only**, and click **Scan now**.
4. Confirm the report contains the file with `Confidential Document` and `Payment Card Data`, and confirm the file has no Velox xattr.
5. Select **Enforce** with **Tag classified files** enabled and scan again.
6. Confirm the report marks the file `tagged` and run:

   ```sh
   xattr -p com.velox.macdlp.classification ~/Documents/<test-file>
   ```

7. Repeat with a mounted writable share, then a read-only share. The writable share should tag when xattrs are supported; the read-only share must still report the finding and record `tag-failed`.
8. Inspect `/Library/Logs/VeloxMacDLP/events.jsonl` and verify no extracted content appears.

## Known limits

- Office/OpenDocument archive extraction is not yet implemented.
- Scheduling runs while the logged-in Velox host agent is active.
- This feature classifies and tags data at rest; quarantine, redaction, and deletion belong to the separate remediation module.
