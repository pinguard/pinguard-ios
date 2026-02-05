//
//  ConfigurationDemoView.swift
//  Example
//
//  Created by Çağatay Eğilmez on 4.02.2026
//

import SwiftUI
import PinGuard

struct ConfigurationDemoView: View {
    var body: some View {
        DemoViewTemplate(
            title: "Configuration",
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
""",
            action: {
                await performConfigurationDemo()
            }
        ) {
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

        var eventCount = 0
        builder.telemetry { _ in
            eventCount += 1
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

#Preview {
    NavigationView {
        ConfigurationDemoView()
    }
}
