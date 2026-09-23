//
//  RemoteConfigView.swift
//  Example
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import CryptoKit
import Foundation
import PinGuard
import SwiftUI

struct RemoteConfigView: View {

    @State private var payload = """
    {
      "version": 1,
      "policySet": {
        "policies": [
          {
            "pattern": "*.example.com",
            "policy": { "pins": [ { "type": "spki", "hash": "NEW_PIN_FROM_YOUR_BACKEND=" } ] }
          }
        ]
      }
    }
    """
    @State private var tamperSignature = false
    @State private var result = "Nothing applied yet."

    var body: some View {
        Form {
            Section("Payload your backend would send") {
                TextEditor(text: $payload)
                    .font(.system(.caption, design: .monospaced))
                    .frame(minHeight: 200)
            }
            Section {
                Toggle("Break the signature on purpose", isOn: $tamperSignature)
                Button("Sign with HMAC and apply") {
                    Task {
                        await apply()
                    }
                }
            }
            Section("Result") {
                Text(result)
            }
        }
        .navigationTitle("Remote config")
    }

    /// Signs the payload with the demo secret and applies it to the shared PinGuard.
    private func apply() async {
        let data = Data(payload.utf8)
        let key = SymmetricKey(data: PinGuardSetup.remoteConfigSecret)
        var signature = Data(HMAC<SHA256>.authenticationCode(for: data, using: key))
        if tamperSignature {
            signature[0] ^= 0xFF
        }
        let blob = RemoteConfigBlob(payload: data, signature: signature, signatureType: .hmacSHA256(secretID: "demo"))
        let verifier = HMACRemoteConfigVerifier { secretID in
            secretID == "demo" ? PinGuardSetup.remoteConfigSecret : nil
        }
        do {
            try await PinGuard.shared.apply(remoteConfig: blob, verifier: verifier)
            let count = await PinGuard.shared.currentConfiguration.activePolicySet.policies.count
            result = "Applied. The active environment now has \(count) host policy(ies)."
        } catch {
            result = "Rejected: \(error)"
        }
    }
}
