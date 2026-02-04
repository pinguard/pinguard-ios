//
//  MTLSDemoView.swift
//  Example
//
//  Created by PinGuard Example on 4.02.2026.
//

import SwiftUI
import PinGuard
import Security

struct MTLSDemoView: View {
    var body: some View {
        DemoViewTemplate(
            title: "mTLS (Mutual TLS)",
            description: "Configure client certificates for mutual authentication.",
            codeSnippet: """
// Load from PKCS12
let source = ClientCertificateSource.pkcs12(
    data: pkcs12Data,
    password: "password"
)
let result = ClientCertificateLoader.loadIdentity(
    from: source
)

// Or from Keychain
let keychainSource = ClientCertificateSource.keychain(
    identityTag: Data("com.example.identity".utf8)
)

// Create provider
let provider = StaticClientCertificateProvider(
    source: source
)

// Configure mTLS
let mtlsConfig = MTLSConfiguration(
    provider: provider,
    onRenewalRequired: {
        print("Certificate renewal needed")
    }
)

// Use in configuration
builder.environment(
    .prod,
    policySet: policySet,
    mtls: mtlsConfig
)
""",
            action: {
                await performMTLSDemo()
            }
        ) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Certificate Sources:")
                    .font(.headline)

                Label(".pkcs12 - Bundle PKCS12 file", systemImage: "doc.fill")
                Label(".keychain - Load from keychain", systemImage: "key.icloud")

                Divider()

                Text("Identity Results:")
                    .font(.headline)

                Label(".success - Identity loaded", systemImage: "checkmark.circle.fill")
                Label(".renewalRequired - Needs renewal", systemImage: "arrow.clockwise")
                Label(".unavailable - Not found", systemImage: "xmark.circle")
            }
            .font(.caption)
        }
    }
}

func performMTLSDemo() async -> String {
    var output = ""

    output += "=== mTLS Configuration ===\n\n"

    // Demonstrate keychain source
    let keychainTag = Data("com.example.client.identity".utf8)
    let keychainSource = ClientCertificateSource.keychain(identityTag: keychainTag)

    output += "✅ Created keychain source\n"
    output += "   Tag: com.example.client.identity\n\n"

    // Demonstrate PKCS12 source (simulated)
    let pkcs12Data = Data("SIMULATED_PKCS12".utf8)
    let pkcs12Source = ClientCertificateSource.pkcs12(
        data: pkcs12Data,
        password: "demo_password"
    )

    output += "✅ Created PKCS12 source\n"
    output += "   Size: \(pkcs12Data.count) bytes\n\n"

    // Create provider
    let provider = StaticClientCertificateProvider(source: keychainSource)
    output += "✅ Created StaticClientCertificateProvider\n\n"

    // Test identity loading (will fail without real identity)
    let result = ClientCertificateLoader.loadIdentity(from: keychainSource)

    switch result {
    case .success(let identity, let chain):
        output += "✅ Identity loaded successfully\n"
        output += "   Chain length: \(chain.count)\n"
    case .renewalRequired:
        output += "⚠️ Certificate renewal required\n"
    case .unavailable:
        output += "ℹ️ Identity not found (expected in demo)\n"
    }

    output += "\n=== MTLSConfiguration ===\n\n"

    var renewalCalled = false
    let mtlsConfig = MTLSConfiguration(
        provider: provider,
        onRenewalRequired: {
            renewalCalled = true
        }
    )

    output += "✅ Created MTLSConfiguration\n"
    output += "✅ Renewal callback configured\n\n"

    output += "Usage:\n"
    output += "1. Bundle PKCS12 or use Keychain\n"
    output += "2. Create ClientCertificateProvider\n"
    output += "3. Pass to environment configuration\n"
    output += "4. Automatic client cert presentation\n"

    return output
}

#Preview {
    NavigationView {
        MTLSDemoView()
    }
}
