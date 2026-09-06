# Network Flow Control

## Signing modes

The checked-in development entitlements use `content-filter-provider`, which is the value Apple requires for Apple Development signing and local testing. Direct distribution outside the Mac App Store must instead use a Developer ID Application certificate, Developer ID provisioning profiles for both the host and network system extension, and the corresponding `content-filter-provider-systemextension` entitlement. Distribution-ready entitlement templates are kept at `Sources/VeloxApp/VeloxMacDLPDeveloperID.entitlements` and `Sources/VeloxNetworkFilter/VeloxNetworkFilterDeveloperID.entitlements`; do not use them with an Apple Development profile.

Both signing modes grant the host and provider the `$(TeamIdentifierPrefix)co.velox.macdlp` application group. The provider's `NEMachServiceName` begins with that exact group, as required by Network Extension validation. Keep the provider sandboxed and keep the group, Mach-service prefix, and provisioning profiles aligned.

## Prototype Contract

VeloxMacDLP provides outbound network flow inspection and policy enforcement via a dedicated Network Extension Content Filter (`co.velox.macdlp.networkfilter`):

- `disabled`: Network flow filtering is bypassed and all socket connections proceed uninspected.
- `audit-only`: Outbound socket flows are matched against rules; matching block rules generate `would-block` audit events while allowing network traffic.
- `enforce`: Outbound socket flows are inspected and actively blocked if they match explicit block rules (or default block when unmatched).

## Policy Model & Evaluation Precedence

1. **Self-Protection & System Daemons**: Invariant checks via `SecurityGuardian` prevent blocking critical macOS networking daemons (`mDNSResponder`, `configd`, `launchd`, `trustd`, `opendirectoryd`, `securityd`) and authentic Velox binaries.
2. **Disabled Mode**: If `networkFlowControl.mode == .disabled`, traffic is immediately allowed.
3. **Explicit Allow Rules (Whitelist)**: Matched allow rules take precedence over block rules.
4. **Explicit Block Rules**: Matched block rules yield `.drop()` in `enforce` mode and `.allow()` with `would-block` audit events in `audit-only` mode.
5. **Default Action**: If unmatched by any rule, `networkFlowControl.defaultAction` (`allow` or `block`) applies.

## Match Criteria

- **Domain / Hostname**: Exact domain matching, hierarchical subdomains (`example.com` matches `api.example.com`), and wildcard patterns (`*.dropbox.com`).
- **IP Address & CIDR Subnets**: Exact IPv4/IPv6 addresses and CIDR subnets (e.g. `10.0.0.0/8`, `192.168.0.0/16`, `2001:db8::/32`) evaluated via zero-dependency bitwise arithmetic.
- **Port & Port Range**: Exact port numbers (e.g. `443`, `8080`) or numeric intervals (`80-443`).
- **Transport Protocol**: `any` (TCP + UDP), `tcp`, or `udp`.
- **Process Identity**: Originating process attributed via Mach audit token, matching `signingId`, `teamId`, `isPlatformBinary`, or `executablePath`.

## Architecture & Topology

- **Dual System Extension Topology**: macOS requires Endpoint Security (`VeloxExtension`) and Content Filter Providers (`VeloxNetworkFilter`) to reside in distinct system extension bundles.
- **NEFilterDataProvider**: Inspects `NEFilterSocketFlow` in `handleNewFlow` for `.outbound` connections.
- **Audit Token Process Attribution**: Converts `flow.sourceProcessAuditToken` into `audit_token_t` and queries `SecCodeCopyGuestWithAttributes` and `proc_pidpath` to resolve signing attributes.
- **Fail-Open Resilience**: If flow context cannot be extracted or evaluation errors occur, flows are permitted fail-open.
- **Authenticated Event Bridge**: The data provider sends blocked/would-block metadata to the signed Velox host over the app-group-scoped NEMachServiceName. The listener rejects callers that are not the Team-ID-bound co.velox.macdlp host.
- **Privacy-Safe Telemetry**: The host forwards those structured events to the root-owned Endpoint Security logging service, which makes them available to Live Activity and native “Blocked by Velox DLP” notifications. Logs record destination hosts or IP addresses, ports, protocol, rule IDs, and process signing identities. Payload data and decrypted traffic contents are never captured or logged.

## Configuration & XPC Management

The module is configured via privileged XPC commands through `VeloxControlProtocol`:
- `setNetworkFlowMode(mode)`
- `setNetworkFlowDefaultAction(action)`
- `addNetworkFlowRule(ruleJSON)`
- `removeNetworkFlowRule(ruleId)`

Policy changes increment `policyVersion` monotonically and persist atomically to `/Library/Application Support/VeloxMacDLP/policy.json`.

The host submits the Content Filter system-extension activation request first and only enables `NEFilterManager` after macOS reports successful activation. The console reports the Network Filter state independently from Endpoint Security, including activation, approval, configuration, failure, restart-required, and enabled states. An active Endpoint Security connection alone is never presented as proof that network filtering is running.

## Manual Acceptance

1. Install and launch the signed app. Approve the new system extension/content filter if macOS asks.
2. Confirm `systemextensionsctl list` shows `co.velox.macdlp.networkfilter` as `[activated enabled]` and the console shows **Filter enabled**.
3. Open Velox Mac DLP and navigate to **Network Flow Control**.
4. Set mode to **Audit only** and Default Action to **Allow**.
5. Add a rule to block domain `example.com` on port range `80-443`.
6. Run `curl https://example.com` in Terminal. The connection should succeed, and an audit event with decision `would-block` should appear in Live Activity.
7. Switch mode to **Enforce**.
8. Run `curl https://example.com`. The connection should be dropped immediately, a `blocked` event should log, and a native notification alert should be displayed.
9. Run `curl https://apple.com`. The connection should succeed as an allowed flow.
10. Delete the rule; verify connections to `example.com` succeed.
