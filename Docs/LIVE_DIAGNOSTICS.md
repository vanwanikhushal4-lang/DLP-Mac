# Live Enforcement Diagnostics

The installed VeloxMacDLP executable includes a read-only terminal console for
development, acceptance testing, and demonstrations:

```sh
/Applications/VeloxMacDLP.app/Contents/MacOS/VeloxMacDLP --live-logs
```

The command displays:

- active Endpoint Security and Network Filter extension versions;
- active policy version, classified-egress mode, and protected channels;
- extension health and deadline-miss counters;
- every new structured enforcement event;
- an event-driven, numbered classified-egress sequence with route attribution,
  source/destination, signed process identity, cache state, OCR method and
  confidence, matched categories/rules, policy reason, kernel response, and
  final content-gate pass or block;
- explicit fail-closed diagnostics when OCR cannot produce a trustworthy result.

The watcher attaches at the end of `events.jsonl`, so historical events are not
replayed by default. It remains silent until extension state, policy, health, or
an enforcement-relevant event changes. Pass `--history` to replay the current
event file before following new records, or `--all-events` to include routine
allowed application launches that are hidden by default.

```sh
/Applications/VeloxMacDLP.app/Contents/MacOS/VeloxMacDLP \
  --live-logs --history
```

Press Control-C to stop. Administrator privileges are normally unnecessary
because this mode only reads the product's operator-readable health, policy, and
structured event files. It does not mutate policy or extension state.

## Privacy boundary

The console may display the file path involved in a DLP decision because that
path already exists in the structured operator event. It displays classification
names, hashes, counts, timing, and confidence, but never extracted OCR text,
clipboard contents, image bytes, or document bytes.

## Classified-egress timeline

The first attempt for an unseen file is held under strict enforcement. The host
then classifies it asynchronously so Vision or PDF processing never runs inside
the Endpoint Security authorization deadline. A sensitive retry produces stage
`TRANSFER BLOCKED`; a clean retry produces `CONTENT GATE PASSED` and may still
be subject to a stricter channel-wide policy. A passed file-access authorization
does not prove that the destination application completed its transmission.

For AirDrop, macOS does not expose the Share Sheet click itself through Endpoint
Security. Detection occurs when Apple's signed `sharingd` service reads the
selected file. USB is reported when `AUTH_COPYFILE` provides the source and the
external-volume destination. These distinctions appear explicitly in the live
console so telemetry is not presented as stronger than the underlying OS signal.
