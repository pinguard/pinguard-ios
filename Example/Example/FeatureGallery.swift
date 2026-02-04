//
//  FeatureGallery.swift
//  Example
//
//  Created by PinGuard Example on 4.02.2026.
//

import SwiftUI

struct FeatureBucket: Identifiable {
    let id = UUID()
    let title: String
    let subtitle: String
    let icon: String
    let destination: AnyView
}

struct FeatureGalleryView: View {
    let features: [FeatureBucket] = [
        FeatureBucket(
            title: "Configuration & Setup",
            subtitle: "Builder pattern, environments, telemetry",
            icon: "gearshape.2.fill",
            destination: AnyView(ConfigurationDemoView())
        ),
        FeatureBucket(
            title: "Pin Creation & Types",
            subtitle: "SPKI, certificate, CA pins with roles",
            icon: "key.fill",
            destination: AnyView(PinGenerationDemoView())
        ),
        FeatureBucket(
            title: "Policy Configuration",
            subtitle: "Host patterns, strategies, trust options",
            icon: "shield.fill",
            destination: AnyView(PolicyConfigDemoView())
        ),
        FeatureBucket(
            title: "Trust Evaluation",
            subtitle: "Direct evaluation with decisions",
            icon: "checkmark.seal.fill",
            destination: AnyView(TrustEvaluationDemoView())
        ),
        FeatureBucket(
            title: "URLSession Integration",
            subtitle: "PinGuardSession & custom delegates",
            icon: "network",
            destination: AnyView(URLSessionDemoView())
        ),
        FeatureBucket(
            title: "mTLS (Mutual TLS)",
            subtitle: "Client certificates & identity loading",
            icon: "lock.shield.fill",
            destination: AnyView(MTLSDemoView())
        ),
        FeatureBucket(
            title: "Events & Telemetry",
            subtitle: "Event logging & chain summaries",
            icon: "chart.line.uptrend.xyaxis",
            destination: AnyView(EventsDemoView())
        ),
        FeatureBucket(
            title: "Remote Configuration",
            subtitle: "Signed config blobs & verification",
            icon: "icloud.and.arrow.down.fill",
            destination: AnyView(RemoteConfigDemoView())
        ),
        FeatureBucket(
            title: "Error Handling",
            subtitle: "All error types & recovery patterns",
            icon: "exclamationmark.triangle.fill",
            destination: AnyView(ErrorHandlingDemoView())
        ),
        FeatureBucket(
            title: "Environment Management",
            subtitle: "Runtime environment switching",
            icon: "switch.2",
            destination: AnyView(EnvironmentDemoView())
        )
    ]

    var body: some View {
        NavigationView {
            List(features) { feature in
                NavigationLink(destination: feature.destination) {
                    HStack(spacing: 16) {
                        Image(systemName: feature.icon)
                            .font(.title2)
                            .foregroundColor(.blue)
                            .frame(width: 40)

                        VStack(alignment: .leading, spacing: 4) {
                            Text(feature.title)
                                .font(.headline)
                            Text(feature.subtitle)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(.vertical, 8)
                }
            }
            .navigationTitle("PinGuard Examples")
        }
    }
}

#Preview {
    FeatureGalleryView()
}
