//
//  ExampleApp.swift
//  Example
//
//  Created by Çağatay Eğilmez on 3.02.2026.
//

import PinGuard
import SwiftUI

@main
struct ExampleApp: App {
    init() {
        PinGuard.configure { builder in
            let activePin = Pin(type: .spki, hash: "Y7EKzelfzqmyMnNRDIX8cecAf6wj1nk7nT25ws/qnVo=", role: .primary)
            let backupPin = Pin(type: .spki, hash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", role: .backup)

            let policy = PinningPolicy(
                pins: [activePin, backupPin],
                failStrategy: .permissive,
                requireSystemTrust: true,
                allowSystemTrustFallback: true
            )

            let policySet = PolicySet(policies: [
                HostPolicy(pattern: .exact("example.com"), policy: policy),
                HostPolicy(pattern: .wildcard("example.com"), policy: policy)
            ])

            builder.environment(.dev, policySet: policySet, mtls: nil)
            builder.environment(.prod, policySet: policySet, mtls: nil)
            builder.selectEnvironment(.dev)

            builder.telemetry { event in
                print("[PinGuard] \(event)")
            }
        }
    }

    var body: some Scene {
        WindowGroup {
            FeatureGalleryView()
        }
    }
}
