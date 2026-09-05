# Nearby Transfer Control

## Prototype contract

Nearby Transfer Control prevents selected macOS transfer services from reading regular files in protected user folders. It is an outbound DLP rule: receiving a file remains allowed because incoming transfers request write access.

The protected services are:

- Apple `sharingd` (`com.apple.sharingd`), which serves AirDrop and other Apple Share Sheet destinations
- Finder's AirDrop helper (`com.apple.finder.Open-AirDrop`)
- Bluetooth File Exchange (`com.apple.BluetoothFileExchange`)
- OBEXAgent (`com.apple.OBEXAgent`)

The default protected folders are Desktop, Documents, Downloads, Movies, Music, Pictures, and Public. The policy can be set to `enforce`, `audit-only`, or `disabled` from the Velox console or through `nearbyTransferControl` in `policy.json`.

## Decision boundary

The Endpoint Security extension handles `ES_EVENT_TYPE_AUTH_OPEN` before the file is opened.

It denies the requested open flags only when all of these are true:

1. The feature is enabled for the detected transfer channel.
2. The actor matches a known Apple nearby-sharing or Bluetooth file-transfer service.
3. The target is a regular file beneath a configured protected user folder.
4. The open is read-only data access.
5. The target is not a partial browser download, application bundle, or system metadata file.

An enforce-mode denial is recorded as module `nearby-transfer-control`, with an action of `apple-sharing-file-open`, `airdrop-file-open`, or `bluetooth-file-open`. A user notification is emitted only after Endpoint Security confirms that the deny response was accepted.

## Manual acceptance test

Use a signed build with the Endpoint Security system extension approved and active.

1. Open VeloxMacDLP, select **AirDrop & Bluetooth**, and choose **Enforce**.
2. Put a uniquely named test file in Documents.
3. Try to send it by AirDrop to a second Apple device. The transfer must fail, the Velox notification must identify a nearby transfer block, and the live activity entry must include the file path.
4. If a compatible Bluetooth/OBEX receiver is available, repeat with Bluetooth File Exchange. The same three outcomes are required.
5. Receive a uniquely named file into Downloads. Receiving must succeed and must not create a blocked event.
6. Confirm a Bluetooth keyboard, mouse, headset, and normal local file opening still work.
7. Switch to **Audit only** and repeat the outbound test. The transfer must succeed and the event must say `would-block`.
8. Switch to **Disabled** and repeat. The transfer must succeed with no nearby-transfer candidate decision.

Inspect the local evidence stream with:

```sh
tail -f "/Library/Application Support/VeloxMacDLP/events.jsonl"
```

## Production boundary

Endpoint Security identifies the process reading a file, but does not expose which destination the user selected inside the Share Sheet. Consequently, a protected-file read by `sharingd` is logged as **Apple nearby sharing** and can also stop non-AirDrop Share Sheet routes that use the same process. This is deliberate fail-closed behavior for the prototype and must be included in acceptance testing.

For a complete device-wide AirDrop prohibition, deploy Apple's Restrictions payload with `allowAirDrop=false` through MDM. The local agent rule complements that restriction with file-level evidence; it is not a replacement for device management. Bluetooth accessory control and Bluetooth settings lockdown are separate controls from Bluetooth file-transfer DLP.

Third-party transfer applications are not automatically treated as Apple's Nearby Share service. Add their verified signing identities as explicit policy channels only after capturing their Endpoint Security process evidence and testing their incoming/outgoing access pattern.
