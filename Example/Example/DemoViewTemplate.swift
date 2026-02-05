//
//  DemoViewTemplate.swift
//  Example
//
//  Created by Çağatay Eğilmez on 4.02.2026
//

import SwiftUI

struct DemoViewTemplate<Content: View>: View {

    let title: String
    let description: String
    let codeSnippet: String
    let action: () async -> String

    @ViewBuilder let content: Content

    @State private var isRunning = false
    @State private var output: String = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Description")
                        .font(.headline)
                    Text(description)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }

                Divider()

                VStack(alignment: .leading, spacing: 8) {
                    Text("Code")
                        .font(.headline)
                    Text(codeSnippet)
                        .font(.system(.caption, design: .monospaced))
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color(.systemGray6))
                        .cornerRadius(8)
                }

                Divider()

                content

                Button(action: {
                    Task {
                        isRunning = true
                        output = await action()
                        isRunning = false
                    }
                }) {
                    HStack {
                        if isRunning {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle())
                        } else {
                            Image(systemName: "play.fill")
                        }
                        Text("Run Demo")
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .cornerRadius(10)
                }
                .disabled(isRunning)

                if !output.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Output")
                            .font(.headline)
                        Text(output)
                            .font(.system(.caption, design: .monospaced))
                            .padding()
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color(.systemGray6))
                            .cornerRadius(8)
                    }
                }
            }
            .padding()
        }
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
    }
}
