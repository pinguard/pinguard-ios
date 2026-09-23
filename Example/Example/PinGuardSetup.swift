//
//  PinGuardSetup.swift
//  Example
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Foundation
import PinGuard

nonisolated enum PinGuardSetup {

    static let host = "example.com"
    static let primaryPin = "CFZ1L1MZmmc9zJVcE3/h9bEFoYBSissyC7Pt3xUQOps="
    static let backupPin = "BACKUP_PIN_GOES_HERE_WHEN_YOU_ROTATE_KEYS="
    static let remoteConfigSecret = Data("demo-shared-secret".utf8)

    /// Configures the shared PinGuard with the demo policy and forwards every event to the log.
    ///
    /// - Parameter eventLog: The log that shows events on screen.
    static func configure(eventLog: EventLog) async {
        await PinGuard.configure { builder in
            builder.environment(.prod, policySet: policySet)
            builder.selectEnvironment(.prod)
            builder.addEventSink(EventLogSink(eventLog: eventLog))
        }
    }

    static var policySet: PolicySet {
        let policy = PinningPolicy(pins: [
            Pin(type: .spki, hash: primaryPin, role: .primary),
            Pin(type: .spki, hash: backupPin, role: .backup)
        ],
                                   failStrategy: .strict,
                                   requireSystemTrust: true,
                                   allowSystemTrustFallback: true)
        return PolicySet(policies: [
            HostPolicy(pattern: .exact(host), policy: policy),
            HostPolicy(pattern: .wildcard(host), policy: policy)
        ])
    }
}
