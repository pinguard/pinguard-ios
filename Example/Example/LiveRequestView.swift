//
//  LiveRequestView.swift
//  Example
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import PinGuard
import SwiftUI

struct LiveRequestView: View {

    @Environment(EventLog.self) private var eventLog
    @State private var result = "Tap the button to make a pinned request."
    @State private var isLoading = false

    var body: some View {
        Form {
            Section {
                Text("PinGuardSession is a URLSession that checks every server certificate against your pins.")
                Button("Fetch https://example.com") {
                    Task {
                        await fetch()
                    }
                }
                .disabled(isLoading)
            }
            Section("Result") {
                Text(result)
                    .font(.system(.body, design: .monospaced))
            }
            Section("Events from this request") {
                ForEach(eventLog.entries.prefix(6)) { entry in
                    Text(entry.message)
                        .font(.caption)
                }
            }
        }
        .navigationTitle("Live request")
    }

    /// Performs one request through PinGuardSession and shows the outcome.
    private func fetch() async {
        guard let url = URL(string: "https://\(PinGuardSetup.host)") else {
            return
        }

        isLoading = true
        defer {
            isLoading = false
        }
        do {
            let (data, response) = try await PinGuardSession().data(from: url)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            result = "HTTP \(status), \(data.count) bytes"
        } catch {
            result = "Failed: \(error.localizedDescription)"
        }
    }
}
