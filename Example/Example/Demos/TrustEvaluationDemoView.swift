//
//  TrustEvaluationDemoView.swift
//  Example
//
//  Created by Çağatay Eğilmez on 4.02.2026
//

import PinGuard
import Security
import SwiftUI

struct TrustEvaluationDemoView: View {
    var body: some View {
        DemoViewTemplate(title: "",
                         description: "",
                         codeSnippet: "") {
            await performTrustEvaluationDemo()
        } content: {
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

    let evaluator = TrustEvaluator(policySet: policySet) { event in
        Task { @MainActor in
            printEvent(event)
        }
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
