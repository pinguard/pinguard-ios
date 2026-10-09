//
//  TrustDecision.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

/// The outcome of evaluating one server connection, with the reason and the events behind it.
public struct TrustDecision: Equatable, Sendable {

    /// Whether the connection may proceed.
    public let isTrusted: Bool

    /// Why PinGuard reached this outcome.
    public let reason: TrustDecisionReason

    /// Every event emitted during this evaluation, in order.
    public let events: [PinGuardEvent]

    public init(isTrusted: Bool, reason: TrustDecisionReason, events: [PinGuardEvent]) {
        self.isTrusted = isTrusted
        self.reason = reason
        self.events = events
    }
}
