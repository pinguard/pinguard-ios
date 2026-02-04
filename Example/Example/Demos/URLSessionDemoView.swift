//
//  URLSessionDemoView.swift
//  Example
//
//  Created by PinGuard Example on 4.02.2026.
//

import SwiftUI
import PinGuard

struct URLSessionDemoView: View {
    @State private var sessionOutput = ""

    var body: some View {
        DemoViewTemplate(
            title: "URLSession Integration",
            description: "Use PinGuardSession wrapper or custom delegate for pinning.",
            codeSnippet: """
// Option 1: PinGuardSession (convenience)
let session = PinGuardSession()
let (data, response) = try await session.data(
    for: request
)

// Option 2: Custom delegate
let delegate = PinGuardURLSessionDelegate(
    pinGuard: .shared,
    mtls: mtlsConfig
)
let session = URLSession(
    configuration: .default,
    delegate: delegate,
    delegateQueue: nil
)
""",
            action: {
                await performURLSessionDemo()
            }
        ) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Integration Options:")
                    .font(.headline)

                Label("PinGuardSession - Drop-in replacement", systemImage: "arrow.triangle.swap")
                Label("PinGuardURLSessionDelegate - Custom setup", systemImage: "slider.horizontal.3")

                Divider()

                Button("Test Live Request (example.com)") {
                    Task {
                        await testLiveRequest()
                    }
                }
                .buttonStyle(.bordered)

                if !sessionOutput.isEmpty {
                    Text(sessionOutput)
                        .font(.caption)
                        .padding()
                        .background(Color(.systemGray6))
                        .cornerRadius(8)
                }
            }
        }
    }

    @MainActor
    func testLiveRequest() async {
        sessionOutput = "Making request to example.com...\n"

        let session = PinGuardSession()
        let url = URL(string: "https://example.com")!

        do {
            let (data, response) = try await session.data(from: url)
            if let httpResponse = response as? HTTPURLResponse {
                sessionOutput += "✅ Status: \(httpResponse.statusCode)\n"
                sessionOutput += "✅ Bytes: \(data.count)\n"
            }
        } catch {
            sessionOutput += "❌ Error: \(error.localizedDescription)\n"
        }
    }
}

@MainActor
func performURLSessionDemo() async -> String {
    var output = ""

    output += "=== PinGuardSession ===\n\n"

    // Create session
    let session = PinGuardSession(configuration: .default)
    output += "✅ Created PinGuardSession\n"
    output += "✅ Uses shared PinGuard configuration\n"
    output += "✅ Automatic pinning on all requests\n\n"

    output += "=== Custom Delegate ===\n\n"

    let delegate = PinGuardURLSessionDelegate(pinGuard: .shared, mtls: nil)
    output += "✅ Created PinGuardURLSessionDelegate\n"
    output += "✅ Handles NSURLAuthenticationMethodServerTrust\n"
    output += "✅ Optional mTLS support\n\n"

    output += "Usage:\n"
    output += "1. PinGuardSession for simple cases\n"
    output += "2. Custom delegate for advanced control\n"
    output += "3. Both validate pins automatically\n"

    return output
}

#Preview {
    NavigationView {
        URLSessionDemoView()
    }
}
