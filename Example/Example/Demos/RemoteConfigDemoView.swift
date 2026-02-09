//
//  RemoteConfigDemoView.swift
//  Example
//
//  Created by Çağatay Eğilmez on 4.02.2026
//

import CryptoKit
import PinGuard
import SwiftUI

struct RemoteConfigDemoView: View {
    var body: some View {
        DemoViewTemplate(title: "Remote Configuration",
                         description: "Verify signed configuration blobs using HMAC.",
                         codeSnippet: """
// Create signed blob
let blob = RemoteConfigBlob(
    payload: configData,
    signature: signatureData,
    signatureType: .hmacSHA256(secretID: "key-v1")
)

// HMAC verification
let hmacVerifier = HMACRemoteConfigVerifier { secretID in
    return secretStore[secretID]
}
let isValid = hmacVerifier.verify(blob: blob)

// Public key verification
let pkVerifier = PublicKeyRemoteConfigVerifier { keyID in
    return publicKeyStore[keyID]
}
let isValid = pkVerifier.verify(blob: blob)

// Security warning
print(RemoteConfigThreatModel.unsignedConfigWarning)
""") {
            await performRemoteConfigDemo()
        } content: {
            VStack(alignment: .leading, spacing: 12) {
                Text("Signature Types:")
                    .font(.headline)

                Label(".hmacSHA256 - Shared secret", systemImage: "key.horizontal")
                Label(".publicKey - Asymmetric signature", systemImage: "lock.doc")

                Divider()

                Text("⚠️ Security Warning:")
                    .font(.headline)
                    .foregroundColor(.orange)

                Text(RemoteConfigThreatModel.unsignedConfigWarning)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

func performRemoteConfigDemo() async -> String {
    var output = ""

    output += "=== Remote Configuration ===\n\n"

    // Demo payload
    let payload = Data("{ \"version\": 1, \"policies\": [] }".utf8)

    output += "Payload size: \(payload.count) bytes\n\n"

    // HMAC example
    output += "=== HMAC Verification ===\n\n"

    let secret = Data("demo-secret-key".utf8)
    let key = SymmetricKey(data: secret)
    let mac = HMAC<SHA256>.authenticationCode(for: payload, using: key)
    let signature = Data(mac)

    let hmacBlob = RemoteConfigBlob(payload: payload,
                                    signature: signature,
                                    signatureType: .hmacSHA256(secretID: "demo-key-v1"))

    let hmacVerifier = HMACRemoteConfigVerifier { secretID in
        guard secretID == "demo-key-v1" else {
            return nil
        }

        return secret
    }

    let hmacValid = hmacVerifier.verify(blob: hmacBlob)
    output += "✅ HMAC blob created\n"
    output += "✅ Signature: \(signature.base64EncodedString().prefix(32))...\n"
    output += "✅ Verification: \(hmacValid ? "VALID" : "INVALID")\n\n"

    // Public key example
    output += "=== Public Key Verification ===\n\n"

    let privateKey = P256.Signing.PrivateKey()
    guard let pkSignature = try? privateKey.signature(for: payload) else {
        return output + "❌ Failed to create signature"
    }

    let publicKeyData = privateKey.publicKey.x963Representation

    let pkBlob = RemoteConfigBlob(payload: payload,
                                  signature: pkSignature.rawRepresentation,
                                  signatureType: .publicKey(keyID: "demo-pk-v1"))

    let pkVerifier = PublicKeyRemoteConfigVerifier { [publicKeyData] keyID in
        guard keyID == "demo-pk-v1" else {
            return nil
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        return SecKeyCreateWithData(publicKeyData as CFData, attributes as CFDictionary, nil)
    }

    let pkValid = pkVerifier.verify(blob: pkBlob)
    output += "✅ EC P-256 key generated\n"
    output += "✅ Signature created\n"
    output += "✅ Verification: \(pkValid ? "VALID" : "INVALID")\n\n"

    output += "=== Security Model ===\n\n"
    output += RemoteConfigThreatModel.unsignedConfigWarning

    return output
}
