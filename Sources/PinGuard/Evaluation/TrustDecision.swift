//
//  TrustDecision.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

public struct TrustDecision: Equatable, Sendable {

    public let isTrusted: Bool
    public let reason: TrustDecisionReason
    public let events: [PinGuardEvent]

    public init(isTrusted: Bool, reason: TrustDecisionReason, events: [PinGuardEvent]) {
        self.isTrusted = isTrusted
        self.reason = reason
        self.events = events
    }
}
