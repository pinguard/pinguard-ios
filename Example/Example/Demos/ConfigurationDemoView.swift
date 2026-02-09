//
//  ConfigurationDemoView.swift
//  Example
//
//  Created by Çağatay Eğilmez on 4.02.2026
//

import PinGuard
import SwiftUI

struct ConfigurationDemoView: View {
    var body: some View {
        DemoViewTemplate(title: "Configuration",
                         description: "Configure PinGuard with multiple environments using the Builder pattern.",
                         codeSnippet: """
PinGuard.configure { builder in
    let pin = Pin(type: .spki, hash: "abc...")
    let policy = PinningPolicy(pins: [pin])
    let policySet = PolicySet(policies: [
        HostPolicy(pattern: .exact("api.example.com"),
                   policy: policy)
    ])

    builder.environment(.dev, policySet: policySet)
    builder.environment(.prod, policySet: policySet)
    builder.selectEnvironment(.dev)

    builder.telemetry { event in
        print("Event: \\(event)")
    }
}
""") {
            await performConfigurationDemo()
        } content: {
            VStack(alignment: .leading, spacing: 12) {
                Text("Features:")
                    .font(.headline)

                Label("Multiple environments (dev, uat, prod)", systemImage: "server.rack")
                Label("Per-environment policy sets", systemImage: "list.bullet")
                Label("Telemetry callback for events", systemImage: "chart.bar")
                Label("Dynamic environment selection", systemImage: "arrow.left.arrow.right")
            }
            .font(.subheadline)
        }
    }
}

@MainActor
func performConfigurationDemo() async -> String {
    var output = ""

    PinGuard.configure { builder in
        let devPin = Pin(type: .spki, hash: "DEV_HASH_123", role: .primary)
        let prodPin = Pin(type: .spki, hash: "PROD_HASH_456", role: .primary)

        let devPolicy = PinningPolicy(pins: [devPin], failStrategy: .permissive)
        let prodPolicy = PinningPolicy(pins: [prodPin], failStrategy: .strict)

        builder.environment(.dev, policySet: PolicySet(policies: [
            HostPolicy(pattern: .exact("dev.example.com"), policy: devPolicy)
        ]))

        builder.environment(.prod, policySet: PolicySet(policies: [
            HostPolicy(pattern: .exact("api.example.com"), policy: prodPolicy)
        ]))

        builder.selectEnvironment(.dev)

        builder.telemetry { event in
            Task { @MainActor in
                printEvent(event)
            }
        }

        output += "✅ Configured 2 environments\n"
        output += "✅ Selected environment: dev\n"
        output += "✅ Telemetry handler installed\n"
    }

    let config = PinGuard.shared.currentConfiguration()
    output += "\nCurrent environment: \(config.current.name)\n"
    output += "Active policies: \(config.activePolicySet.policies.count)\n"

    return output
}

private func printEvent(_ event: PinGuardEvent) {
    var eventDescription = "Unknown event"
    switch event {
    case .policyMissing(let host):
        eventDescription = "Policy missing for \(host)"
    case .systemTrustEvaluated(let host, let isTrusted):
        eventDescription = "Trust for \(host) is \(isTrusted ? "trusted" : "not trusted")"
    case .systemTrustFailed(let host, let error):
        eventDescription = "Trust evaluation for \(host) failed: \(error ?? "")"
    case .systemTrustFailedPermissive(let host):
        eventDescription = "Trust evaluation for \(host) failed in permissive mode"
    case .chainSummary(let host, let summary):
        eventDescription = "Trust evaluation for \(host): \(summary)"
    case .pinMatched(let host, let pins):
        eventDescription = "Pin(s) for \(host) match: \(pins.map(\.hash).joined(separator: ", "))"
    case .pinMismatch(let host):
        eventDescription = "No pin(s) found for \(host)"
    case .pinMismatchAllowedByFallback(let host):
        eventDescription = "No pin(s) found for \(host), falling back"
    case .pinMismatchPermissive(let host):
        eventDescription = "No pin(s) found for \(host), falling back (permissive mode)"
    case .pinSetEmpty(let host):
        eventDescription = "No pins set for \(host)"
    case .mtlsIdentityUsed(let host):
        eventDescription = "MTLS identity for \(host) is being used"
    case .mtlsIdentityMissing(let host):
        eventDescription = "No MTLS identity available for \(host)"
    }
    print(eventDescription)
}
