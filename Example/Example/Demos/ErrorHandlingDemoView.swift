//
//  ErrorHandlingDemoView.swift
//  Example
//
//  Created by PinGuard Example on 4.02.2026.
//

import SwiftUI
import PinGuard

struct ErrorHandlingDemoView: View {
    var body: some View {
        DemoViewTemplate(
            title: "Error Handling",
            description: "Handle all PinGuardError types and implement recovery strategies.",
            codeSnippet: """
do {
    let hash = try PinHasher.spkiHash(for: key)
    // Use hash...
} catch PinGuardError.unsupportedKeyType {
    print("Key type not supported")
} catch PinGuardError.invalidPin {
    print("Invalid pin format")
} catch {
    print("Unexpected error: \\(error)")
}

// Check trust decision
let decision = PinGuard.shared.evaluate(
    serverTrust: trust,
    host: host
)

if !decision.isTrusted {
    switch decision.reason {
    case .policyMissing:
        // No policy configured for host
    case .trustFailed:
        // System trust validation failed
    case .pinningFailed:
        // Pin validation failed
    default:
        break
    }
}
""",
            action: {
                await performErrorHandlingDemo()
            }
        ) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Error Types:")
                    .font(.headline)

                VStack(alignment: .leading, spacing: 6) {
                    Label(".invalidHost", systemImage: "network.slash")
                    Label(".policyNotFound", systemImage: "doc.questionmark")
                    Label(".trustEvaluationFailed", systemImage: "xmark.seal")
                    Label(".trustNotTrusted", systemImage: "exclamationmark.shield")
                    Label(".pinningFailed", systemImage: "key.slash")
                    Label(".unsupportedKeyType", systemImage: "key.slash")
                    Label(".invalidPin", systemImage: "questionmark.key.filled")
                    Label(".invalidCertificate", systemImage: "doc.badge.exclamationmark")
                    Label(".mtlsIdentityUnavailable", systemImage: "person.crop.circle.badge.xmark")
                }
                .font(.caption)
            }
        }
    }
}

func performErrorHandlingDemo() async -> String {
    var output = ""

    output += "=== PinGuardError Cases ===\n\n"

    let errorCases: [(PinGuardError, String)] = [
        (.invalidHost, "Host validation failed"),
        (.policyNotFound, "No policy configured for host"),
        (.trustEvaluationFailed, "SecTrust evaluation error"),
        (.trustNotTrusted, "Server not trusted by system"),
        (.pinningFailed, "Pin validation failed"),
        (.unsupportedKeyType, "Key algorithm not supported"),
        (.invalidPin, "Pin format or data invalid"),
        (.invalidCertificate, "Certificate parsing failed"),
        (.mtlsIdentityUnavailable, "Client certificate not found")
    ]

    for (error, description) in errorCases {
        output += "• \(error)\n  \(description)\n\n"
    }

    output += "=== Recovery Strategies ===\n\n"

    output += "1. Policy Missing:\n"
    output += "   - Add wildcard/default policy\n"
    output += "   - Log for monitoring\n\n"

    output += "2. Trust Failed:\n"
    output += "   - Check system trust first\n"
    output += "   - Use permissive mode cautiously\n\n"

    output += "3. Pin Mismatch:\n"
    output += "   - Verify pin hashes are current\n"
    output += "   - Use backup pins for rotation\n"
    output += "   - Consider allowSystemTrustFallback\n\n"

    output += "4. mTLS Identity Missing:\n"
    output += "   - Trigger onRenewalRequired\n"
    output += "   - Prompt user to re-authenticate\n\n"

    output += "=== Decision Reasons ===\n\n"

    let reasons: [(TrustDecision.Reason, String)] = [
        (.pinMatch, "✅ Success - Pin validated"),
        (.systemTrustAllowed, "✅ Success - System trust OK"),
        (.systemTrustFailedPermissive, "⚠️ Warning - Permissive mode"),
        (.pinMismatchAllowedByFallback, "⚠️ Warning - Fallback allowed"),
        (.pinMismatchPermissive, "⚠️ Warning - Permissive mode"),
        (.trustFailed, "❌ Error - Trust validation failed"),
        (.policyMissing, "❌ Error - No policy found"),
        (.pinningFailed, "❌ Error - Pin validation failed")
    ]

    for (reason, description) in reasons {
        output += "\(description)\n"
    }

    return output
}

#Preview {
    NavigationView {
        ErrorHandlingDemoView()
    }
}
