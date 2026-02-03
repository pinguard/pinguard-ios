//
//  ExampleApp.swift
//  Example
//
//  Created by Çağatay Eğilmez on 3.02.2026.
//

import SwiftUI
import PinGuard

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
                allowSystemTrustFallback: false
            )
            let policySet = PolicySet(policies: [
                HostPolicy(pattern: .exact("example.com"), policy: policy),
                HostPolicy(pattern: .wildcard("example.com"), policy: policy)
            ])
            builder.environment(.dev, policySet: policySet, mtls: nil)
            builder.selectEnvironment(.dev)
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
