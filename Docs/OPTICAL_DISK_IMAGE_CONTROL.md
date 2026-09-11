# Optical & Disk Image Control

## Product contract

Optical & Disk Image Control prevents covered file-backed images and physical optical media from becoming mounted volumes on the Mac. It is a mount-control feature, not a file deletion feature: users may retain or download `.dmg` and `.iso` files, but enforce mode denies the operating-system mount operation.

The policy exposes two independent targets:

- `blockDiskImages`: virtual file-backed mounts, including DMG, ISO, sparseimage, and sparsebundle volumes.
- `blockOpticalMedia`: physical CD/DVD media recognized through optical filesystem metadata.

Both targets support `enforce`, `audit-only`, and `disabled` modes. An active policy must select at least one target.

## Enforcement flow

1. The Endpoint Security system extension subscribes to `ES_EVENT_TYPE_AUTH_MOUNT` and `ES_EVENT_TYPE_AUTH_REMOUNT`.
2. The extension extracts mount source, destination, filesystem type, and Apple's mount disposition from the authorization message.
3. `PolicyEngine.evaluateOpticalDiskImageMount` performs an in-memory decision before the mount is completed.
4. Enforce mode responds `DENY`; audit-only responds `ALLOW` and records `would-block`; disabled and unrelated mounts respond `ALLOW`.
5. Covered decisions are written to the structured event log. Successful denials trigger a native “Blocked by Velox DLP” notification and appear in the React activity panel.

Disk images are detected by `ES_MOUNT_DISPOSITION_VIRTUAL`, not the source filename. This is more reliable than checking `.dmg` or `.iso` suffixes and intentionally covers any virtual file-backed volume macOS reports through that disposition.

Physical optical media is detected by a case-insensitive filesystem allowlist:

- `cd9660` (ISO 9660 data discs)
- `cddafs` (audio CDs)
- `udf` and `udf2` (common DVD/optical media formats)

Internal, network, and nullfs dispositions are never treated as physical optical candidates. Unexpected or unrecognized metadata fails open.

## USB encrypted-container compatibility

The USB Encryption feature mounts its own encrypted APFS sparse bundle. A blanket virtual-mount denial would otherwise block that trusted workflow.

`ManagedVirtualMountAllowance` provides a short-lived, in-memory authorization scoped to the container attach operation. A mount is exempt only when all of these conditions hold:

- the USB encryption coordinator currently owns an unexpired token;
- the actor is an authentic Apple platform binary from the disk-image/mount stack;
- the destination name is exactly `Velox Secure USB`, optionally followed by macOS's numeric duplicate-volume suffix.

The token is removed as soon as `hdiutil attach` returns. A spoofed signing ID without the platform-binary attribute, an arbitrary process, or a lookalike volume name is not accepted.

## Policy example

```json
{
  "opticalDiskImageControl": {
    "mode": "enforce",
    "blockDiskImages": true,
    "blockOpticalMedia": true
  }
}
```

The local React console sends the complete three-field configuration through the authenticated XPC control channel. The extension validates, persists, and activates the new monotonically increasing policy version.

## Privacy-safe event shape

Events use module `optical-disk-image-control` and one of these actions:

- `disk-image-mount`
- `disk-image-remount`
- `optical-media-mount`
- `optical-media-remount`

Telemetry contains process identity, mount source/destination, filesystem type, rule ID, decision, policy version, response result, and decision latency. It does not read or log files stored inside the volume.

## Manual acceptance

Start with audit-only so the expected mount can be confirmed without interruption, then repeat in enforce mode.

### Disk image

1. Create or obtain a harmless test DMG.
2. Set Disk images on and Optical media to either state.
3. In audit-only, open the DMG. It must mount and produce a `would-block` disk-image event.
4. Eject it, switch to enforce, and open it again. The volume must not mount, the app must show a blocked event, and macOS must show the Velox notification.
5. Disable Disk images and verify the same DMG mounts normally.

### Physical optical media

1. Connect a supported external optical drive and insert a data CD or DVD.
2. Set Optical media on.
3. In audit-only, confirm the disc mounts and creates a `would-block` optical-media event.
4. Eject it, switch to enforce, and reinsert it. The disc must remain unmounted with a notification and blocked event.
5. Disable Optical media and verify the disc mounts normally.

### Regression boundaries

- The internal startup volume must remain available.
- SMB/NFS and other network shares must continue to mount.
- USB Storage Control must still decide physical removable-media mounts according to its own policy.
- With disk images blocked, USB Encryption must still create and mount `Velox Secure USB`.
- A user-created image named `Velox Secure USB` must remain blocked outside the coordinator's active allowance window.

For production fleet enforcement, deploy the notarized agent through MDM and protect system-extension approval/removal with the appropriate management profiles. Local administrator control cannot be made tamper-proof by an unmanaged menu-bar agent alone.
