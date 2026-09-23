//
//  HostMatchingView.swift
//  Example
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import PinGuard
import SwiftUI

struct HostMatchingView: View {

    @State private var host = "api.example.com"

    private let patterns: [HostPattern] = [
        .exact("example.com"),
        .wildcard("example.com"),
        .exact("api.example.com")
    ]

    var body: some View {
        Form {
            Section("Host") {
                TextField("Host", text: $host)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            }
            Section("Patterns") {
                ForEach(patterns, id: \.rawValue) { pattern in
                    LabeledContent(pattern.rawValue) {
                        Image(systemName: HostMatcher.matches(pattern, host: host) ? "checkmark.circle.fill" : "xmark.circle")
                            .foregroundStyle(HostMatcher.matches(pattern, host: host) ? .green : .secondary)
                    }
                }
            }
            Section("Rules") {
                Text("A wildcard covers exactly one label. *.example.com matches api.example.com but not example.com or a.b.example.com.")
                Text("When several patterns match, the exact one wins, then the longest wildcard.")
            }
        }
        .navigationTitle("Host matching")
    }
}
