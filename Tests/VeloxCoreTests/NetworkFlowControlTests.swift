import XCTest
@testable import VeloxCore

final class NetworkFlowControlTests: XCTestCase {

    func testLegacyPolicyDefaultsNetworkFlowControlToDisabled() throws {
        let json = """
        {
          "policyVersion": 1,
          "applicationControl": { "mode": "enforce" }
        }
        """

        let policy = try VeloxPolicy.decodeStrict(from: Data(json.utf8))
        XCTAssertEqual(policy.networkFlowControl.mode, .disabled)
        XCTAssertEqual(policy.networkFlowControl.defaultAction, .allow)
        XCTAssertTrue(policy.networkFlowControl.rules.isEmpty)
    }

    func testNetworkFlowControlStrictDecodingAndUnknownPropertyRejection() throws {
        let json = """
        {
          "policyVersion": 45,
          "applicationControl": { "mode": "enforce" },
          "networkFlowControl": {
            "mode": "enforce",
            "defaultAction": "block",
            "rules": [
              {
                "ruleId": "block-cloud",
                "domain": "dropbox.com",
                "port": 443,
                "protocol": "tcp",
                "action": "block"
              }
            ]
          }
        }
        """

        let policy = try VeloxPolicy.decodeStrict(from: Data(json.utf8))
        XCTAssertEqual(policy.networkFlowControl.mode, .enforce)
        XCTAssertEqual(policy.networkFlowControl.defaultAction, .block)
        XCTAssertEqual(policy.networkFlowControl.rules.count, 1)
        XCTAssertEqual(policy.networkFlowControl.rules[0].ruleId, "block-cloud")
        XCTAssertEqual(policy.networkFlowControl.rules[0].domain, "dropbox.com")
        XCTAssertEqual(policy.networkFlowControl.rules[0].port, 443)
        XCTAssertEqual(policy.networkFlowControl.rules[0].protocol, .tcp)
        XCTAssertEqual(policy.networkFlowControl.rules[0].action, "block")

        let invalid = json.replacingOccurrences(
            of: "\"action\": \"block\"",
            with: "\"action\": \"block\", \"unknownKey\": 123"
        )
        XCTAssertThrowsError(try VeloxPolicy.decodeStrict(from: Data(invalid.utf8))) { error in
            guard case PolicyValidationError.unknownProperty = error else {
                XCTFail("Expected unknownProperty, got \(error)")
                return
            }
        }
    }

    func testNetworkMatcherDomainMatching() {
        // Exact and Subdomain matching
        XCTAssertTrue(NetworkMatcher.matchesDomain("example.com", target: "example.com"))
        XCTAssertTrue(NetworkMatcher.matchesDomain("example.com", target: "api.example.com"))
        XCTAssertTrue(NetworkMatcher.matchesDomain("example.com", target: "sub.api.example.com"))
        XCTAssertFalse(NetworkMatcher.matchesDomain("example.com", target: "notexample.com"))
        XCTAssertFalse(NetworkMatcher.matchesDomain("example.com", target: "example.com.org"))

        // Wildcard matching
        XCTAssertTrue(NetworkMatcher.matchesDomain("*.dropbox.com", target: "dl.dropbox.com"))
        XCTAssertTrue(NetworkMatcher.matchesDomain("*.dropbox.com", target: "dropbox.com"))
        XCTAssertFalse(NetworkMatcher.matchesDomain("*.dropbox.com", target: "google.com"))

        // Case insensitivity
        XCTAssertTrue(NetworkMatcher.matchesDomain("ExAmPlE.CoM", target: "API.EXAMPLE.COM"))
    }

    func testNetworkMatcherIPv4AndCIDRMatching() {
        // Single IP
        XCTAssertTrue(NetworkMatcher.matchesIP("192.168.1.100", target: "192.168.1.100"))
        XCTAssertFalse(NetworkMatcher.matchesIP("192.168.1.100", target: "192.168.1.101"))

        // IPv4 CIDR /24
        XCTAssertTrue(NetworkMatcher.matchesCIDR("192.168.1.0/24", target: "192.168.1.1"))
        XCTAssertTrue(NetworkMatcher.matchesCIDR("192.168.1.0/24", target: "192.168.1.254"))
        XCTAssertFalse(NetworkMatcher.matchesCIDR("192.168.1.0/24", target: "192.168.2.1"))

        // IPv4 CIDR /16
        XCTAssertTrue(NetworkMatcher.matchesCIDR("10.10.0.0/16", target: "10.10.250.5"))
        XCTAssertFalse(NetworkMatcher.matchesCIDR("10.10.0.0/16", target: "10.11.1.1"))

        // IPv4 CIDR /32 and /0
        XCTAssertTrue(NetworkMatcher.matchesCIDR("1.2.3.4/32", target: "1.2.3.4"))
        XCTAssertFalse(NetworkMatcher.matchesCIDR("1.2.3.4/32", target: "1.2.3.5"))
        XCTAssertTrue(NetworkMatcher.matchesCIDR("0.0.0.0/0", target: "203.0.113.195"))
    }

    func testNetworkMatcherIPv6AndCIDRMatching() {
        // Single IPv6
        XCTAssertTrue(NetworkMatcher.matchesIP("2001:db8::1", target: "2001:0db8:0000:0000:0000:0000:0000:0001"))
        XCTAssertFalse(NetworkMatcher.matchesIP("2001:db8::1", target: "2001:db8::2"))

        // IPv6 CIDR /64
        XCTAssertTrue(NetworkMatcher.matchesCIDR("2001:db8:abcd:0012::/64", target: "2001:db8:abcd:0012:0000:0000:0000:0001"))
        XCTAssertTrue(NetworkMatcher.matchesCIDR("2001:db8:abcd:0012::/64", target: "2001:db8:abcd:12::ffff"))
        XCTAssertFalse(NetworkMatcher.matchesCIDR("2001:db8:abcd:0012::/64", target: "2001:db8:abcd:0013::1"))
    }

    func testNetworkMatcherPortAndPortRangeMatching() {
        // Single Port
        XCTAssertTrue(NetworkMatcher.matchesPort(exact: 443, range: nil, target: 443))
        XCTAssertFalse(NetworkMatcher.matchesPort(exact: 443, range: nil, target: 80))

        // Port Range
        XCTAssertTrue(NetworkMatcher.matchesPort(exact: nil, range: "80-443", target: 80))
        XCTAssertTrue(NetworkMatcher.matchesPort(exact: nil, range: "80-443", target: 200))
        XCTAssertTrue(NetworkMatcher.matchesPort(exact: nil, range: "80-443", target: 443))
        XCTAssertFalse(NetworkMatcher.matchesPort(exact: nil, range: "80-443", target: 444))
        XCTAssertFalse(NetworkMatcher.matchesPort(exact: nil, range: "80-443", target: 79))
    }

    func testNetworkMatcherProtocolMatching() {
        XCTAssertTrue(NetworkMatcher.matchesProtocol(.any, target: .tcp))
        XCTAssertTrue(NetworkMatcher.matchesProtocol(.any, target: .udp))
        XCTAssertTrue(NetworkMatcher.matchesProtocol(.tcp, target: .tcp))
        XCTAssertFalse(NetworkMatcher.matchesProtocol(.tcp, target: .udp))
        XCTAssertTrue(NetworkMatcher.matchesProtocol(.udp, target: .udp))
        XCTAssertFalse(NetworkMatcher.matchesProtocol(.udp, target: .tcp))
    }

    func testPolicyEngineNetworkFlowEvaluation() {
        let policy = VeloxPolicy(
            policyVersion: 1,
            applicationControl: ApplicationControlConfig(mode: .disabled),
            networkFlowControl: NetworkFlowControlConfig(
                mode: .enforce,
                defaultAction: .allow,
                rules: [
                    NetworkDestinationRule(
                        ruleId: "whitelist-dns",
                        ipAddress: "1.1.1.1",
                        port: 53,
                        protocol: .udp,
                        action: "allow"
                    ),
                    NetworkDestinationRule(
                        ruleId: "block-exfil-domain",
                        domain: "exfiltrate.data",
                        port: 443,
                        protocol: .tcp,
                        action: "block"
                    ),
                    NetworkDestinationRule(
                        ruleId: "block-bad-subnet",
                        cidrRange: "198.51.100.0/24",
                        action: "block"
                    )
                ]
            )
        )

        let engine = PolicyEngine(policy: policy)

        let proc = ProcessContext(
            pid: 1234,
            parentPid: 1,
            signingId: "com.user.app",
            teamId: "ABCDEF1234",
            isPlatformBinary: false,
            cdhash: "0123456789abcdef",
            executablePath: "/Applications/UserApp.app/Contents/MacOS/UserApp"
        )

        // 1. Matched allow rule
        let allowContext = NetworkFlowContext(
            process: proc,
            remoteHostname: nil,
            remoteAddress: "1.1.1.1",
            remotePort: 53,
            ipProtocol: .udp
        )
        let allowDecision = engine.evaluateNetworkFlow(allowContext)
        XCTAssertEqual(allowDecision.decisionString, "allowed")
        XCTAssertTrue(allowDecision.shouldAllowFlow)
        XCTAssertEqual(allowDecision.matchingRuleId, "whitelist-dns")

        // 2. Matched block rule in enforce mode
        let blockContext = NetworkFlowContext(
            process: proc,
            remoteHostname: "api.exfiltrate.data",
            remoteAddress: "203.0.113.5",
            remotePort: 443,
            ipProtocol: .tcp
        )
        let blockDecision = engine.evaluateNetworkFlow(blockContext)
        XCTAssertEqual(blockDecision.decisionString, "blocked")
        XCTAssertFalse(blockDecision.shouldAllowFlow)
        XCTAssertEqual(blockDecision.matchingRuleId, "block-exfil-domain")

        // 3. Matched CIDR block rule
        let cidrContext = NetworkFlowContext(
            process: proc,
            remoteHostname: nil,
            remoteAddress: "198.51.100.42",
            remotePort: 8080,
            ipProtocol: .tcp
        )
        let cidrDecision = engine.evaluateNetworkFlow(cidrContext)
        XCTAssertEqual(cidrDecision.decisionString, "blocked")
        XCTAssertFalse(cidrDecision.shouldAllowFlow)
        XCTAssertEqual(cidrDecision.matchingRuleId, "block-bad-subnet")

        // 4. Unmatched traffic with default allow
        let fallbackContext = NetworkFlowContext(
            process: proc,
            remoteHostname: "apple.com",
            remoteAddress: "17.253.144.10",
            remotePort: 443,
            ipProtocol: .tcp
        )
        let fallbackDecision = engine.evaluateNetworkFlow(fallbackContext)
        XCTAssertEqual(fallbackDecision.decisionString, "allowed")
        XCTAssertTrue(fallbackDecision.shouldAllowFlow)
        XCTAssertNil(fallbackDecision.matchingRuleId)

        // 5. Critical system process bypass (trustd)
        let trustdProc = ProcessContext(
            pid: 88,
            parentPid: 1,
            signingId: "com.apple.trustd",
            teamId: "",
            isPlatformBinary: true,
            cdhash: "abcdef0123456789",
            executablePath: "/usr/libexec/trustd"
        )
        let trustdContext = NetworkFlowContext(
            process: trustdProc,
            remoteHostname: "exfiltrate.data",
            remoteAddress: "203.0.113.5",
            remotePort: 443,
            ipProtocol: .tcp
        )
        let trustdDecision = engine.evaluateNetworkFlow(trustdContext)
        XCTAssertEqual(trustdDecision.decisionString, "allowed")
        XCTAssertTrue(trustdDecision.shouldAllowFlow)
    }

    func testNetworkFlowAuditOnlyMode() {
        let policy = VeloxPolicy(
            policyVersion: 2,
            applicationControl: ApplicationControlConfig(mode: .disabled),
            networkFlowControl: NetworkFlowControlConfig(
                mode: .auditOnly,
                defaultAction: .block,
                rules: [
                    NetworkDestinationRule(
                        ruleId: "block-test",
                        domain: "test.com",
                        action: "block"
                    )
                ]
            )
        )

        let engine = PolicyEngine(policy: policy)
        let proc = ProcessContext(
            pid: 456,
            parentPid: 1,
            signingId: "com.curl",
            teamId: "",
            isPlatformBinary: false,
            cdhash: "",
            executablePath: "/usr/bin/curl"
        )

        let context = NetworkFlowContext(
            process: proc,
            remoteHostname: "test.com",
            remoteAddress: "192.0.2.1",
            remotePort: 80,
            ipProtocol: .tcp
        )

        let decision = engine.evaluateNetworkFlow(context)
        XCTAssertEqual(decision.decisionString, "would-block")
        XCTAssertTrue(decision.shouldAllowFlow) // Flows are permitted in audit-only
        XCTAssertEqual(decision.matchingRuleId, "block-test")
    }

    func testNetworkFlowFailsOpenWhenSourceAttributionIsUnavailable() {
        let policy = VeloxPolicy(
            policyVersion: 3,
            applicationControl: ApplicationControlConfig(mode: .disabled),
            networkFlowControl: NetworkFlowControlConfig(
                mode: .enforce,
                defaultAction: .block,
                rules: []
            )
        )
        let engine = PolicyEngine(policy: policy)
        let unknownProcess = ProcessContext(
            pid: 0,
            parentPid: 0,
            signingId: nil,
            teamId: nil,
            isPlatformBinary: false,
            cdhash: nil,
            executablePath: "unknown"
        )
        let context = NetworkFlowContext(
            process: unknownProcess,
            remoteHostname: "example.com",
            remoteAddress: "198.51.100.10",
            remotePort: 443,
            ipProtocol: .tcp
        )

        let decision = engine.evaluateNetworkFlow(context)
        XCTAssertEqual(decision.decisionString, "allowed")
        XCTAssertTrue(decision.shouldAllowFlow)
        XCTAssertNil(decision.matchingRuleId)
    }

    func testNetworkFlowNotificationFormatting() {
        let formatted = VeloxNotificationFormatter.format(
            module: "network-flow-control",
            action: "socket-connect",
            target: "api.dropbox.com",
            detail: "/Applications/Dropbox.app/Contents/MacOS/Dropbox"
        )

        XCTAssertEqual(formatted.title, "Blocked by Velox DLP")
        XCTAssertEqual(formatted.subtitle, "Network Connection Blocked")
        XCTAssertEqual(
            formatted.body,
            "Velox DLP blocked api.dropbox.com for Dropbox."
        )
    }
}
