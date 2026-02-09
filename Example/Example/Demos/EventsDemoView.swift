//
//  EventsDemoView.swift
//  Example
//
//  Created by Çağatay Eğilmez on 4.02.2026
//

import PinGuard
import SwiftUI

struct EventsDemoView: View {
    @State private var events: [String] = []

    var body: some View {
        DemoViewTemplate(title: "Events & Telemetry",
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
""") {
            await performEventsDemo()
        } content: {
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
    output += "=== PinGuard Events ===\n\n"

    PinGuard.configure { builder in
        let pin = Pin(type: .spki, hash: "TEST_HASH")
        let policy = PinningPolicy(pins: [pin])
        builder.environment(.dev, policySet: PolicySet(policies: [
            HostPolicy(pattern: .exact("test.com"), policy: policy)
        ]))
        builder.selectEnvironment(.dev)

        builder.telemetry { event in
            Task { @MainActor in
                printEvent(event)
            }
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
