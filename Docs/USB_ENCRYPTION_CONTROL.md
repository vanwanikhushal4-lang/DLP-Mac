# USB Encryption / Container

## Prototype contract

VeloxMacDLP supports a removable-media encryption policy inside USB Storage Control:

- `disabled`: encrypted-container enforcement does not inspect or deny USB writes.
- `audit-only`: physical media remains writable and plaintext mutations are logged as `would-encrypt`; no container is created automatically.
- `enforce`: the physical drive mounts, Velox creates and mounts an AES-256 encrypted APFS sparse bundle, and direct plaintext writes to the outer volume are denied.

Whole-device mount blocking and encrypted-container enforcement are different policies. Enabling encrypted-container audit or enforcement disables whole-device blocking so the outer drive can mount. Selecting USB mount enforcement disables container mode.

## On-disk layout

For each connected physical external volume, Velox creates:

```text
<USB volume>/.velox/container-id
<USB volume>/.velox/VeloxSecure.sparsebundle
```

The sparse bundle is formatted as APFS and encrypted by `hdiutil` with AES-256. Its virtual capacity defaults to 90% of the physical volume capacity and it grows sparsely as data is written. It is mounted in `/Volumes` with the visible volume name `Velox Secure USB`.

Users copy files into `Velox Secure USB`, not into the physical outer volume. Endpoint Security denies ordinary `AUTH_OPEN`, `AUTH_CREATE`, and `AUTH_COPYFILE` mutations to the outer volume while allowing only the authenticated Velox ES client and exact Apple disk-image helpers to update `.velox`.

## Key handling

The prototype generates a random 256-bit passphrase per container. Keys are stored at:

```text
/Library/Application Support/VeloxMacDLP/usb-container-keys.json
```

The file is owned by root and set to mode `0600`. Passphrases are sent to `hdiutil` through standard input and are never included in process arguments, events, or UI responses.

This local key store is intentionally a prototype boundary. Production deployment must wrap each device key with a backend-managed tenant key, escrow the wrapped key through the authenticated policy channel, define recovery/rotation/revocation, and support another authorized Mac opening the media. Never deploy this prototype as the sole copy of a business recovery key.

## Privacy-safe events

The module name is `usb-encryption-control`. Events record the outer volume, coarse operation, decision, policy version, and acting process identity. File names, file contents, passphrases, and container bytes are not logged.

## Manual acceptance

Use a disposable USB drive with no irreplaceable data.

1. Connect the drive and confirm it appears in Finder.
2. Open VeloxMacDLP, select **USB Storage Control**, and set **USB encryption / container** to **Audit only**.
3. Copy a harmless file to the physical drive. The copy must succeed and a `would-encrypt` event must appear.
4. Set container mode to **Enforce**. Wait until the dashboard reports `1/1` containers ready and Finder shows **Velox Secure USB**.
5. Copy a harmless file directly to the physical drive. The copy must fail before content is written, a `blocked` event must appear, and macOS must show **Blocked by Velox DLP**.
6. Copy the same file into **Velox Secure USB**. It must succeed.
7. Eject the secure volume and then the physical drive. Reconnect it; Velox must attach the same container using the retained key.
8. Verify the event log contains no tested file names or passphrases.
9. Repeat with exFAT and APFS media, Finder drag/drop, copy/paste, Terminal `cp`, overwriting an existing outer-volume file, and the `copyfile` syscall on every supported macOS release.

## Known boundaries

- Endpoint Security cannot redirect a Finder copy, so the secure volume is a separate visible destination.
- The prototype protects standard write/create/copyfile paths. Production hardening must red-team every filesystem mutation API, symlink/path-truncation behavior, sudden removal, sleep/wake, multiple simultaneous devices, full media, and damaged containers.
- Existing plaintext files already on a drive are not migrated or deleted automatically.
- Audit mode observes; it does not encrypt.
- Container removal and key-loss recovery deliberately fail closed without overwriting an existing sparse bundle.
