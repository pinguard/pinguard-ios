//
//  PinHashView.swift
//  Example
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import PinGuard
import Security
import SwiftUI

struct PinHashView: View {

    @State private var certificateBase64 = ""
    @State private var spkiHash = ""
    @State private var certificateHash = ""
    @State private var errorMessage = ""

    var body: some View {
        Form {
            Section("Paste a certificate (Base64 DER, no PEM header lines)") {
                TextEditor(text: $certificateBase64)
                    .font(.system(.caption, design: .monospaced))
                    .frame(minHeight: 120)
                Button("Compute pins") {
                    compute()
                }
                .disabled(certificateBase64.isEmpty)
            }
            Section("SPKI pin (recommended)") {
                Text(spkiHash.isEmpty ? "-" : spkiHash)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
            }
            Section("Certificate pin") {
                Text(certificateHash.isEmpty ? "-" : certificateHash)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
            }
            if !errorMessage.isEmpty {
                Section {
                    Text(errorMessage)
                        .foregroundStyle(.red)
                }
            }
            Section("Get the certificate from a terminal") {
                Text("openssl s_client -connect example.com:443 -servername example.com </dev/null | openssl x509")
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
            }
        }
        .navigationTitle("Pin from certificate")
    }

    /// Decodes the pasted certificate and computes both pin hashes.
    private func compute() {
        let cleaned = certificateBase64.filter { !$0.isWhitespace }
        guard let der = Data(base64Encoded: cleaned),
              let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
            errorMessage = "That is not a valid Base64 DER certificate."
            return
        }

        errorMessage = ""
        certificateHash = PinHasher.certificateHash(for: certificate)
        if let key = SecCertificateCopyKey(certificate), let hash = try? PinHasher.spkiHash(for: key) {
            spkiHash = hash
        } else {
            spkiHash = "Unsupported key type"
        }
    }
}
