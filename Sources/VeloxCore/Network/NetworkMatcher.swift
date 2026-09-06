import Foundation
import Darwin

public enum NetworkMatcher {
    /// Matches a destination domain or hostname against a rule pattern.
    /// Supports exact matching ("example.com"), subdomain prefixes (".example.com", "*.example.com"),
    /// and standard domain hierarchies (e.g. "example.com" matches "api.example.com").
    public static func matchesDomain(pattern: String, hostname: String) -> Bool {
        let trimmedPattern = pattern.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let trimmedHost = hostname.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        guard !trimmedPattern.isEmpty, !trimmedHost.isEmpty else { return false }

        // Strip trailing dots
        let normPattern = trimmedPattern.hasSuffix(".") ? String(trimmedPattern.dropLast()) : trimmedPattern
        let normHost = trimmedHost.hasSuffix(".") ? String(trimmedHost.dropLast()) : trimmedHost

        if normPattern == normHost {
            return true
        }

        // Wildcard prefix: "*.domain.com" or "*domain.com"
        if normPattern.hasPrefix("*.") {
            let baseDomain = String(normPattern.dropFirst(2))
            if normHost == baseDomain || normHost.hasSuffix("." + baseDomain) {
                return true
            }
        }

        // Dot prefix: ".domain.com"
        if normPattern.hasPrefix(".") {
            let baseDomain = String(normPattern.dropFirst(1))
            if normHost == baseDomain || normHost.hasSuffix("." + baseDomain) {
                return true
            }
        }

        // Standard domain match: "domain.com" matches "sub.domain.com"
        if normHost.hasSuffix("." + normPattern) {
            return true
        }

        return false
    }

    public static func matchesDomain(_ pattern: String, target: String) -> Bool {
        matchesDomain(pattern: pattern, hostname: target)
    }

    /// Matches a destination IP address string against a rule IP address.
    public static func matchesIP(ruleIP: String, flowIP: String) -> Bool {
        let trimmedRule = ruleIP.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedFlow = flowIP.trimmingCharacters(in: .whitespacesAndNewlines)

        guard !trimmedRule.isEmpty, !trimmedFlow.isEmpty else { return false }

        var sinRule4 = sockaddr_in()
        var sinFlow4 = sockaddr_in()
        if inet_pton(AF_INET, trimmedRule, &sinRule4.sin_addr) == 1 &&
           inet_pton(AF_INET, trimmedFlow, &sinFlow4.sin_addr) == 1 {
            return sinRule4.sin_addr.s_addr == sinFlow4.sin_addr.s_addr
        }

        var sinRule6 = sockaddr_in6()
        var sinFlow6 = sockaddr_in6()
        if inet_pton(AF_INET6, trimmedRule, &sinRule6.sin6_addr) == 1 &&
           inet_pton(AF_INET6, trimmedFlow, &sinFlow6.sin6_addr) == 1 {
            return memcmp(&sinRule6.sin6_addr, &sinFlow6.sin6_addr, MemoryLayout<in6_addr>.size) == 0
        }

        return false
    }

    public static func matchesIP(_ ruleIP: String, target: String) -> Bool {
        matchesIP(ruleIP: ruleIP, flowIP: target)
    }

    /// Matches a destination IP address against an IPv4 or IPv6 CIDR block (e.g. "10.0.0.0/8", "2001:db8::/32").
    public static func matchesCIDR(cidr: String, flowIP: String) -> Bool {
        let trimmedCIDR = cidr.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedFlow = flowIP.trimmingCharacters(in: .whitespacesAndNewlines)

        guard !trimmedCIDR.isEmpty, !trimmedFlow.isEmpty else { return false }

        let parts = trimmedCIDR.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let prefix = Int(parts[1]),
              prefix >= 0 else { return false }

        let baseIP = String(parts[0])

        // IPv4 Check
        var sinBase4 = sockaddr_in()
        var sinFlow4 = sockaddr_in()
        if inet_pton(AF_INET, baseIP, &sinBase4.sin_addr) == 1 &&
           inet_pton(AF_INET, trimmedFlow, &sinFlow4.sin_addr) == 1 {
            guard prefix <= 32 else { return false }
            if prefix == 0 { return true }

            let baseInt = UInt32(bigEndian: sinBase4.sin_addr.s_addr)
            let flowInt = UInt32(bigEndian: sinFlow4.sin_addr.s_addr)
            let mask: UInt32 = prefix == 32 ? 0xFFFFFFFF : ~((UInt32(1) << (32 - prefix)) - 1)

            return (baseInt & mask) == (flowInt & mask)
        }

        // IPv6 Check
        var sinBase6 = sockaddr_in6()
        var sinFlow6 = sockaddr_in6()
        if inet_pton(AF_INET6, baseIP, &sinBase6.sin6_addr) == 1 &&
           inet_pton(AF_INET6, trimmedFlow, &sinFlow6.sin6_addr) == 1 {
            guard prefix <= 128 else { return false }
            if prefix == 0 { return true }

            var baseBytes = [UInt8](repeating: 0, count: 16)
            var flowBytes = [UInt8](repeating: 0, count: 16)
            withUnsafeBytes(of: sinBase6.sin6_addr) { buffer in
                baseBytes = Array(buffer)
            }
            withUnsafeBytes(of: sinFlow6.sin6_addr) { buffer in
                flowBytes = Array(buffer)
            }

            let fullBytes = prefix / 8
            let remainingBits = prefix % 8

            for i in 0..<fullBytes {
                if baseBytes[i] != flowBytes[i] {
                    return false
                }
            }

            if remainingBits > 0 {
                let mask: UInt8 = UInt8(0xFF << (8 - remainingBits))
                if (baseBytes[fullBytes] & mask) != (flowBytes[fullBytes] & mask) {
                    return false
                }
            }

            return true
        }

        return false
    }

    public static func matchesCIDR(_ cidr: String, target: String) -> Bool {
        matchesCIDR(cidr: cidr, flowIP: target)
    }

    /// Evaluates if a given destination port matches a single port or port range.
    public static func matchesPort(singlePort: Int?, portRange: String?, flowPort: Int) -> Bool {
        if let p = singlePort {
            if p != flowPort {
                return false
            }
        }

        if let pr = portRange {
            let trimmed = pr.trimmingCharacters(in: .whitespacesAndNewlines)
            let parts = trimmed.split(separator: "-", omittingEmptySubsequences: false)
            if parts.count == 2,
               let start = Int(parts[0]),
               let end = Int(parts[1]) {
                if flowPort < start || flowPort > end {
                    return false
                }
            } else {
                return false
            }
        }

        return true
    }

    public static func matchesPort(exact: Int? = nil, range: String? = nil, target: Int) -> Bool {
        matchesPort(singlePort: exact, portRange: range, flowPort: target)
    }

    /// Evaluates protocol matching.
    public static func matchesProtocol(ruleProtocol: NetworkProtocol, flowProtocol: NetworkProtocol) -> Bool {
        if ruleProtocol == .any || flowProtocol == .any {
            return true
        }
        return ruleProtocol == flowProtocol
    }

    public static func matchesProtocol(_ ruleProtocol: NetworkProtocol, target: NetworkProtocol) -> Bool {
        matchesProtocol(ruleProtocol: ruleProtocol, flowProtocol: target)
    }
}
