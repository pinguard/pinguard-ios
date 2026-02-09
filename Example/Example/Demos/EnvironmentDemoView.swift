//
//  EnvironmentDemoView.swift
//  Example
//
//  Created by Çağatay Eğilmez on 4.02.2026
//

import PinGuard
import SwiftUI

struct EnvironmentDemoView: View {
    @State private var currentEnv: String = "Loading..."
    @State private var policyCount: Int = 0

    var body: some View {
        DemoViewTemplate(title: "Environment Management",
                         description: "Dynamically switch between dev, uat, and prod environments at runtime.",
                         codeSnippet: """
// Configure multiple environments
PinGuard.configure { builder in
    builder.environment(.dev, policySet: devPolicies)
    builder.environment(.uat, policySet: uatPolicies)
    builder.environment(.prod, policySet: prodPolicies)
    builder.selectEnvironment(.dev)
}

// Switch environment at runtime
let newConfig = Configuration(
    environments: existingEnvironments,
    current: .prod
)
PinGuard.shared.update(configuration: newConfig)

// Query current state
let config = PinGuard.shared.currentConfiguration()
print("Current: \\(config.current.name)")
print("Policies: \\(config.activePolicySet.policies.count)")
""") {
            await performEnvironmentDemo()
        } content: {
            VStack(alignment: .leading, spacing: 12) {
                Text("Current Environment:")
                    .font(.headline)

                HStack {
                    Text(currentEnv)
                        .font(.title2)
                        .fontWeight(.bold)

                    Spacer()

                    Text("\(policyCount) policies")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .padding()
                .background(Color.secondary.opacity(0.15))
                .cornerRadius(8)

                Divider()

                Text("Environment Options:")
                    .font(.headline)

                Label(".dev - Development environment", systemImage: "laptopcomputer")
                Label(".uat - User acceptance testing", systemImage: "checkmark.circle")
                Label(".prod - Production environment", systemImage: "server.rack")

                Divider()

                Button("Switch to DEV") {
                    switchEnvironment(to: .dev)
                }
                .buttonStyle(.bordered)

                Button("Switch to PROD") {
                    switchEnvironment(to: .prod)
                }
                .buttonStyle(.bordered)
            }
            .font(.caption)
        }
        .task {
            await updateCurrentState()
        }
    }

    @MainActor
    func switchEnvironment(to env: PinGuard.Configuration.Environment) {
        let currentConfig = PinGuard.shared.currentConfiguration()
        let newConfig = PinGuard.Configuration(
            environments: currentConfig.environments,
            current: env,
            telemetry: currentConfig.telemetry
        )
        PinGuard.shared.update(configuration: newConfig)

        Task {
            await updateCurrentState()
        }
    }

    @MainActor
    func updateCurrentState() async {
        let config = PinGuard.shared.currentConfiguration()
        currentEnv = config.current.name
        policyCount = config.activePolicySet.policies.count
    }
}

@MainActor
func performEnvironmentDemo() async -> String {
    var output = ""

    output += "=== Environment Setup ===\n\n"

    // Configure three environments
    PinGuard.configure { builder in
        let devPin = Pin(type: .spki, hash: "DEV_HASH")
        let uatPin = Pin(type: .spki, hash: "UAT_HASH")
        let prodPin = Pin(type: .spki, hash: "PROD_HASH")

        builder.environment(.dev, policySet: PolicySet(policies: [
            HostPolicy(pattern: .exact("dev.example.com"),
                       policy: PinningPolicy(pins: [devPin],
                                             failStrategy: .permissive))
        ]))

        builder.environment(.uat, policySet: PolicySet(policies: [
            HostPolicy(pattern: .exact("uat.example.com"),
                       policy: PinningPolicy(pins: [uatPin],
                                             failStrategy: .strict))
        ]))

        builder.environment(.prod, policySet: PolicySet(policies: [
            HostPolicy(pattern: .exact("api.example.com"),
                       policy: PinningPolicy(pins: [prodPin],
                                             failStrategy: .strict))
        ]))

        builder.selectEnvironment(.dev)
    }

    output += "✅ Configured 3 environments\n"
    output += "   • dev (permissive)\n"
    output += "   • uat (strict)\n"
    output += "   • prod (strict)\n\n"

    // Query current state
    let config = PinGuard.shared.currentConfiguration()
    output += "Current environment: .\(config.current.name)\n"
    output += "Active policies: \(config.activePolicySet.policies.count)\n\n"

    // Demonstrate switching
    output += "=== Runtime Switching ===\n\n"

    let environments: [PinGuard.Configuration.Environment] = [.dev, .prod]

    for env in environments {
        let newConfig = PinGuard.Configuration(
            environments: config.environments,
            current: env,
            telemetry: config.telemetry
        )
        PinGuard.shared.update(configuration: newConfig)

        let updated = PinGuard.shared.currentConfiguration()
        output += "✅ Switched to .\(updated.current.name)\n"
        output += "   Policies: \(updated.activePolicySet.policies.count)\n"
    }

    output += "\n=== Custom Environments ===\n\n"
    output += "Create custom environments:\n"
    let customEnv = PinGuard.Configuration.Environment("staging")
    output += "✅ Environment(\"\(customEnv.name)\")\n"

    return output
}

#Preview {
    NavigationView {
        EnvironmentDemoView()
    }
}
