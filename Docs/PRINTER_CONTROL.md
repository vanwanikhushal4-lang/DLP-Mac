# Printer Control

## Prototype contract

Printer Control manages physical printer queues through the macOS CUPS scheduler. It supports:

- `enforce`: reject new jobs, stop every configured printer queue, and cancel jobs already queued;
- `audit-only`: leave queues unchanged and record newly observed pending jobs;
- `disabled`: do not audit or control queues, and restore queues previously changed by Velox.

The prototype checks queue state every second. A printer added or re-enabled while enforcement is active is rejected and stopped on the next reconciliation pass.

## Enforcement flow

1. The root system extension runs `/usr/bin/lpstat` directly, with a fixed executable path and C locale, to enumerate printer and job state.
2. Before changing a queue, Velox persists its original enabled and job-acceptance state to `/Library/Application Support/VeloxMacDLP/printer-state.json` with mode `0600`.
3. It invokes `/usr/sbin/cupsreject` to reject new jobs and `/usr/sbin/cupsdisable -c` to stop the queue and cancel pending jobs. Arguments are passed directly to `Process`; no shell evaluates printer names.
4. The coordinator logs a structured `printer-control` event and sends **Blocked by Velox DLP** to the host console.
5. When enforcement ends, Velox restores only the properties it changed. A queue that was already stopped or rejecting jobs before Velox intervened is not incorrectly enabled.

Printer telemetry includes only the queue name, coarse action, decision, and policy version. It does not collect document titles, document paths, rendered spool data, or content.

## Manual acceptance test

This Mac currently has no configured printer destination, so real-device acceptance requires a Mac with a USB, network, or AirPrint queue installed.

1. Confirm the queue starts enabled and accepting jobs:

   ```sh
   lpstat -p
   lpstat -a
   ```

2. Open VeloxMacDLP, select **Printer Control**, then choose **Enforce**.
3. Within one second, confirm the queue is disabled and not accepting jobs. Its reason should mention Velox DLP.
4. Attempt to print from TextEdit, Preview, Safari, and Microsoft Office. No physical page should print, and the job must not remain queued.
5. Add or manually re-enable a second printer while Enforce remains active. Velox must control it on the next reconciliation pass.
6. Choose **Audit only**. Velox must restore queues it changed. Submit a job and confirm a `would-block` event appears without a document title or content in the log.
7. Choose **Disabled** and confirm original queue state remains restored.
8. Repeat with USB, IPP/network, and AirPrint destinations on every supported macOS release.

Inspect evidence with:

```sh
tail -f "/Library/Logs/VeloxMacDLP/events.jsonl"
```

## macOS boundary and production phase

Endpoint Security has no dedicated print-job authorization event. Queue reconciliation is effective for the prototype but an administrator can create or re-enable a queue between checks, and OS printing behavior must be revalidated on each macOS release.

The spreadsheet scope calls for auditing, classified-content blocking, and watermarking. The latter two are not implemented by queue blocking. They require a separately signed CUPS filter that receives rendered job data, invokes the classification engine, denies or transforms the job, and is tested against driverless AirPrint plus vendor drivers. Managed deployment should also apply the applicable MDM printing restrictions to reduce bypass and tampering.

**Save as PDF is not covered here.** It does not submit to a physical CUPS queue and belongs to the separate Print-to-PDF/File Control module.
