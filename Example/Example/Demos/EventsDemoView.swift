//
//  EventsDemoView.swift
//  Example
//
//  Created by Çağatay Eğilmez on 4.02.2026
//

import SwiftUI
import PinGuard

struct EventsDemoView: View {
    @State private var events: [String] = []

    var body: some View {
        DemoViewTemplate(
            title: "Events & Telemetry",
            description: "Capture and log all PinGuard events for monitoring and debugging.",
            codeSnippet: """
PinGuard.configure { builder in
    // ... policy setup ...

    builder.telemetry { event in
        switch event {
        case .policyMissing(let host):
            print("No policy for: \\(host)")
        case .pinMatched(let host, let pins):
            print("✅ Pin matched: \\(host)")
        case .systemTrustFailed(let host, let error):
            print("❌ Trust failed: \\(host)")
        case .chainSummary(let host, let summary):
            print("Chain: \\(summary.leafCommonName ?? "-")")
        // ... handle other events ...
        default:
            print("Event: \\(event)")
        }
    }
}

// Or use built-in logger
PinGuardLogger.log(event)
""",
            action: {
                await performEventsDemo()
            }
        ) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Event Types:")
                    .font(.headline)

                ScrollView(.horizontal, showsIndicators: false) {
                    VStack(alignment: .leading, spacing: 4) {
                        Label("policyMissing", systemImage: "questionmark.circle")
                        Label("systemTrustEvaluated", systemImage: "checkmark.seal")
                        Label("systemTrustFailed", systemImage: "xmark.seal")
                        Label("pinMatched", systemImage: "key.fill")
                        Label("pinMismatch", systemImage: "key.slash")
                        Label("chainSummary", systemImage: "link")
                        Label("mtlsIdentityUsed", systemImage: "lock.shield")
                    }
                    .font(.caption)
                }

                if !events.isEmpty {
                    Divider()
                    Text("Captured Events:")
                        .font(.headline)

                    ScrollView {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(events.indices, id: \.self) { index in
                                Text("\(index + 1). \(events[index])")
                                    .font(.caption2)
                            }
                        }
                    }
                    .frame(maxHeight: 150)
                }
            }
        }
    }
}

@MainActor
func performEventsDemo() async -> String {
    var output = ""
    var capturedEvents: [PinGuardEvent] = []

    output += "=== PinGuard Events ===\n\n"

    // Configure with telemetry
    PinGuard.configure { builder in
        let pin = Pin(type: .spki, hash: "TEST_HASH")
        let policy = PinningPolicy(pins: [pin])
        builder.environment(.dev, policySet: PolicySet(policies: [
            HostPolicy(pattern: .exact("test.com"), policy: policy)
        ]))
        builder.selectEnvironment(.dev)

        builder.telemetry { event in
            capturedEvents.append(event)
        }
    }

    output += "✅ Telemetry configured\n\n"

    output += "Event Types:\n"

    let eventDescriptions: [(String, String)] = [
        ("policyMissing", "No policy found for host"),
        ("systemTrustEvaluated", "System trust check result"),
        ("systemTrustFailed", "System trust validation failed"),
        ("systemTrustFailedPermissive", "Failed but allowed"),
        ("chainSummary", "Certificate chain info"),
        ("pinMatched", "Pin validation succeeded"),
        ("pinMismatch", "Pin validation failed"),
        ("pinMismatchAllowedByFallback", "Allowed by fallback"),
        ("pinMismatchPermissive", "Allowed in permissive mode"),
        ("pinSetEmpty", "No pins configured"),
        ("mtlsIdentityUsed", "Client cert presented"),
        ("mtlsIdentityMissing", "Client cert unavailable")
    ]

    for (name, desc) in eventDescriptions {
        output += "• .\(name)\n  \(desc)\n"
    }

    output += "\n=== ChainSummary ===\n\n"
    output += "Provides certificate chain metadata:\n"
    output += "• leafCommonName: End entity CN\n"
    output += "• issuerCommonName: Issuer CN\n"
    output += "• sanCount: Subject Alternative Names\n"

    return output
}

#Preview {
    NavigationView {
        EventsDemoView()
    }
}
