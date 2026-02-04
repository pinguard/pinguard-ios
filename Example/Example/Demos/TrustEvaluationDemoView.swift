//
//  TrustEvaluationDemoView.swift
//  Example
//
//  Created by PinGuard Example on 4.02.2026.
//

import SwiftUI
import PinGuard
import Security

struct TrustEvaluationDemoView: View {
    var body: some View {
        DemoViewTemplate(
            title: "Trust Evaluation",
            description: "Directly evaluate server trust and inspect decisions.",
            codeSnippet: """
let decision = PinGuard.shared.evaluate(
    serverTrust: trust,
    host: "api.example.com"
)

if decision.isTrusted {
    print("✅ Trusted: \\(decision.reason)")
} else {
    print("❌ Rejected: \\(decision.reason)")
}

// Inspect events
for event in decision.events {
    print("Event: \\(event)")
}

// Manual evaluator
let evaluator = TrustEvaluator(
    policySet: policySet,
    eventSink: { event in
        print("Event: \\(event)")
    }
)
""",
            action: {
                await performTrustEvaluationDemo()
            }
        ) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Decision Reasons:")
                    .font(.headline)

                Label(".pinMatch - Pin validated", systemImage: "checkmark.circle.fill")
                Label(".systemTrustAllowed - System trust OK", systemImage: "lock.fill")
                Label(".pinMismatchPermissive - Allowed with warning", systemImage: "exclamationmark.triangle")
                Label(".pinningFailed - Pin validation failed", systemImage: "xmark.circle.fill")
                Label(".policyMissing - No policy found", systemImage: "questionmark.circle")
            }
            .font(.caption)
        }
    }
}

@MainActor
func performTrustEvaluationDemo() async -> String {
    var output = ""

    // Configure for demo
    let pin = Pin(type: .spki, hash: "DEMO_HASH_123", role: .primary)
    let policy = PinningPolicy(pins: [pin], failStrategy: .strict)
    let policySet = PolicySet(policies: [
        HostPolicy(pattern: .exact("demo.example.com"), policy: policy)
    ])

    output += "=== Trust Evaluation (Simulated) ===\n\n"
    output += "Note: Real evaluation requires actual SecTrust from URLSession\n\n"

    // Demonstrate TrustEvaluator creation
    var capturedEvents: [PinGuardEvent] = []

    let evaluator = TrustEvaluator(policySet: policySet) { event in
        capturedEvents.append(event)
    }

    output += "✅ Created TrustEvaluator\n"
    output += "✅ Configured event sink\n\n"

    output += "Policy Set:\n"
    output += "  Policies: \(policySet.policies.count)\n"
    output += "  First host: demo.example.com\n"
    output += "  Pins: \(policy.pins.count)\n"
    output += "  Strategy: .\(policy.failStrategy)\n\n"

    output += "Decision Reasons:\n"
    let reasons: [TrustDecision.Reason] = [
        .pinMatch,
        .systemTrustAllowed,
        .systemTrustFailedPermissive,
        .pinMismatchAllowedByFallback,
        .pinMismatchPermissive,
        .trustFailed,
        .policyMissing,
        .pinningFailed
    ]

    for reason in reasons {
        output += "  • .\(reason)\n"
    }

    return output
}

#Preview {
    NavigationView {
        TrustEvaluationDemoView()
    }
}
