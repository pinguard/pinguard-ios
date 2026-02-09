//
//  PolicyConfigDemoView.swift
//  Example
//
//  Created by Çağatay Eğilmez on 4.02.2026
//

import PinGuard
import SwiftUI

struct PolicyConfigDemoView: View {
    var body: some View {
        DemoViewTemplate(title: "Policy Configuration",
                         description: "Configure pinning policies with host patterns.",
                         codeSnippet: """
// Exact host pattern
let exactPattern = HostPattern.exact("api.example.com")

// Wildcard pattern (matches *.example.com)
let wildcardPattern = HostPattern.wildcard("example.com")

// Parse from string
let parsed = HostPattern.parse("*.cdn.example.com")

// Test pattern matching
let matches = HostMatcher.matches(wildcardPattern,
                                  host: "api.example.com")

// Create policy with strategies
let policy = PinningPolicy(
    pins: [pin1, pin2],
    failStrategy: .strict,
    requireSystemTrust: true,
    allowSystemTrustFallback: false
)

// Policy set with default
let policySet = PolicySet(
    policies: [
        HostPolicy(pattern: exactPattern, policy: policy)
    ],
    defaultPolicy: fallbackPolicy
)
""") {
            await performPolicyConfigDemo()
        } content: {
            VStack(alignment: .leading, spacing: 12) {
                Text("Host Patterns:")
                    .font(.headline)

                Label(".exact(\"api.example.com\") - Exact match only", systemImage: "equal.circle")
                Label(".wildcard(\"example.com\") - Matches *.example.com", systemImage: "asterisk.circle")

                Divider()

                Text("Fail Strategies:")
                    .font(.headline)

                Label(".strict - Reject on pin mismatch", systemImage: "xmark.shield")
                Label(".permissive - Allow with warning", systemImage: "checkmark.shield.fill")

                Divider()

                Text("Trust Options:")
                    .font(.headline)

                Label("requireSystemTrust - Check system trust", systemImage: "checkmark.seal")
                Label("allowSystemTrustFallback - Fallback option", systemImage: "arrow.uturn.backward")
            }
            .font(.caption)
        }
    }
}

func performPolicyConfigDemo() async -> String {
    var output = ""

    output += "=== Host Pattern Matching ===\n\n"

    let exactPattern = HostPattern.exact("api.example.com")
    let wildcardPattern = HostPattern.wildcard("example.com")

    let testHosts = [
        "api.example.com",
        "www.example.com",
        "example.com",
        "sub.api.example.com"
    ]

    for host in testHosts {
        let exactMatch = HostMatcher.matches(exactPattern, host: host)
        let wildcardMatch = HostMatcher.matches(wildcardPattern, host: host)
        output += "\(host):\n"
        output += "  exact: \(exactMatch ? "✅" : "❌")\n"
        output += "  wildcard: \(wildcardMatch ? "✅" : "❌")\n"
    }

    output += "\n=== Policy Configuration ===\n\n"
    let pin1 = Pin(type: .spki, hash: "PRIMARY_HASH", role: .primary)
    let pin2 = Pin(type: .spki, hash: "BACKUP_HASH", role: .backup)

    let strictPolicy = PinningPolicy(
        pins: [pin1, pin2],
        failStrategy: .strict,
        requireSystemTrust: true,
        allowSystemTrustFallback: false
    )

    let permissivePolicy = PinningPolicy(
        pins: [pin1],
        failStrategy: .permissive,
        requireSystemTrust: false,
        allowSystemTrustFallback: true
    )

    output += "Strict Policy:\n"
    output += "  pins: \(strictPolicy.pins.count)\n"
    output += "  strategy: .\(strictPolicy.failStrategy)\n"
    output += "  requireSystemTrust: \(strictPolicy.requireSystemTrust)\n\n"

    output += "Permissive Policy:\n"
    output += "  pins: \(permissivePolicy.pins.count)\n"
    output += "  strategy: .\(permissivePolicy.failStrategy)\n"
    output += "  allowSystemTrustFallback: \(permissivePolicy.allowSystemTrustFallback)\n\n"

    let policySet = PolicySet(policies: [
        HostPolicy(pattern: .exact("api.example.com"), policy: strictPolicy),
        HostPolicy(pattern: .wildcard("example.com"), policy: permissivePolicy)
    ],
                              defaultPolicy: permissivePolicy
    )

    output += "Policy Set:\n"
    output += "  total policies: \(policySet.policies.count)\n"
    output += "  has default: \(policySet.defaultPolicy != nil)\n"

    return output
}
