//
//  PinGenerationDemoView.swift
//  Example
//
//  Created by PinGuard Example on 4.02.2026.
//

import SwiftUI
import PinGuard
import Security
import CryptoKit

struct PinGenerationDemoView: View {
    var body: some View {
        DemoViewTemplate(
            title: "Pin Generation",
            description: "Generate SPKI and certificate hashes from keys and certificates.",
            codeSnippet: """
// Generate SPKI hash from SecKey
let spkiHash = try PinHasher.spkiHash(for: secKey)

// Generate certificate hash
let certHash = PinHasher.certificateHash(for: cert)

// Create pins with different types
let spkiPin = Pin(type: .spki, hash: spkiHash,
                  role: .primary, scope: .leaf)
let certPin = Pin(type: .certificate, hash: certHash,
                  role: .backup, scope: .any)
let caPin = Pin(type: .ca, hash: caHash,
                role: .primary, scope: .root)
""",
            action: {
                await performPinGenerationDemo()
            }
        ) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Pin Types:")
                    .font(.headline)

                Label(".spki - Subject Public Key Info", systemImage: "key")
                Label(".certificate - Full certificate", systemImage: "doc.text")
                Label(".ca - Certificate Authority", systemImage: "building.columns")

                Divider()

                Text("Pin Roles:")
                    .font(.headline)

                Label(".primary - Active pin", systemImage: "star.fill")
                Label(".backup - Rotation/fallback pin", systemImage: "arrow.triangle.2.circlepath")

                Divider()

                Text("Pin Scopes:")
                    .font(.headline)

                Label(".leaf - End entity certificate", systemImage: "leaf")
                Label(".intermediate - Intermediate CA", systemImage: "link")
                Label(".root - Root CA", systemImage: "tree")
                Label(".any - Match any position", systemImage: "sparkles")
            }
            .font(.caption)
        }
    }
}

func performPinGenerationDemo() async -> String {
    var output = ""

    // Generate a test P-256 key pair
    let privateKey = P256.Signing.PrivateKey()
    let publicKeyData = privateKey.publicKey.rawRepresentation

    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits as String: 256
    ]

    guard let secKey = SecKeyCreateWithData(publicKeyData as CFData, attributes as CFDictionary, nil) else {
        return "❌ Failed to create SecKey"
    }

    output += "🔑 Generated P-256 key pair\n\n"

    // Generate SPKI hash
    do {
        let spkiHash = try PinHasher.spkiHash(for: secKey)
        output += "✅ SPKI Hash:\n\(spkiHash)\n\n"

        // Create pins with different configurations
        let pins = [
            Pin(type: .spki, hash: spkiHash, role: .primary, scope: .leaf),
            Pin(type: .spki, hash: "BACKUP_HASH", role: .backup, scope: .any),
            Pin(type: .certificate, hash: "CERT_HASH", role: .primary, scope: .intermediate),
            Pin(type: .ca, hash: "CA_HASH", role: .primary, scope: .root)
        ]

        output += "✅ Created \(pins.count) pins:\n"
        for (index, pin) in pins.enumerated() {
            output += "\(index + 1). type=.\(pin.type) role=.\(pin.role) scope=.\(pin.scope)\n"
        }

    } catch {
        output += "❌ Error: \(error.localizedDescription)\n"
    }

    return output
}

#Preview {
    NavigationView {
        PinGenerationDemoView()
    }
}
