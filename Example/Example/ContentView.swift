//
//  ContentView.swift
//  Example
//
//  Created by Çağatay Eğilmez on 3.02.2026.
//

import SwiftUI
import PinGuard

struct ContentView: View {
    @State private var status: String = "Idle"

    var body: some View {
        VStack {
            Text("PinGuard Example")
                .font(.headline)
            Text(status)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.bottom, 12)
            Button("Request (pin OK)") {
                Task { await perform(url: URL(string: "https://example.com")!) }
            }
            Button("Request (pin fail)") {
                Task { await perform(url: URL(string: "https://www.apple.com")!) }
            }
            Button("Rotation (backup pin)") {
                Task { await perform(url: URL(string: "https://example.com")!) }
            }
        }
        .padding()
    }

    private func perform(url: URL) async {
        let request = URLRequest(url: url)
        let session = PinGuardSession()
        do {
            let (_, response) = try await session.data(for: request)
            status = "Success: \(response.url?.absoluteString ?? "-")"
        } catch {
            status = "Failed: \(error.localizedDescription)"
        }
    }
}

#Preview {
    ContentView()
}
