//
//  TrustEvaluator.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Security

public struct TrustEvaluator: Sendable {

    private let policyResolver: PolicyResolver
    private let dispatcher: EventDispatcher
    private let systemTrustEvaluator: any SystemTrustEvaluating
    private let pinMatcher = PinMatcher()

    public init(policySet: PolicySet,
                eventSinks: [any PinGuardEventSink] = []) {
        self.init(policySet: policySet,
                  eventSinks: eventSinks,
                  systemTrustEvaluator: SecTrustSystemEvaluator())
    }

    init(policySet: PolicySet,
         eventSinks: [any PinGuardEventSink],
         systemTrustEvaluator: any SystemTrustEvaluating) {
        self.policyResolver = PolicyResolver(policySet: policySet)
        self.dispatcher = EventDispatcher(sinks: eventSinks)
        self.systemTrustEvaluator = systemTrustEvaluator
    }

    /// Evaluates the server trust and configured pins for the given host and returns a trust decision.
    ///
    /// - Parameters:
    ///   - serverTrust: The SecTrust object representing the server's certificate chain.
    ///   - host: The hostname to evaluate.
    /// - Returns: The trust decision together with every event emitted on the way.
    public func evaluate(serverTrust: SecTrust, host: String) async -> TrustDecision {
        var events: [PinGuardEvent] = []
        let normalizedHost = HostPattern.normalizeHost(host)
        guard let policy = policyResolver.resolve(host: normalizedHost) else {
            dispatcher.emit(.policyMissing(host: normalizedHost), into: &events)
            return TrustDecision(isTrusted: false, reason: .policyMissing, events: events)
        }

        let systemTrust = await systemTrustEvaluator.evaluate(serverTrust, host: normalizedHost)
        dispatcher.emit(.systemTrustEvaluated(host: normalizedHost, isTrusted: systemTrust.isTrusted), into: &events)

        if policy.requireSystemTrust && !systemTrust.isTrusted {
            if policy.failStrategy == .permissive {
                dispatcher.emit(.systemTrustFailedPermissive(host: normalizedHost), into: &events)
                return TrustDecision(isTrusted: true, reason: .systemTrustFailedPermissive, events: events)
            }
            dispatcher.emit(.systemTrustFailed(host: normalizedHost, error: systemTrust.errorDescription),
                            into: &events)
            return TrustDecision(isTrusted: false, reason: .trustFailed, events: events)
        }

        return evaluate(chain: CertificateChain(trust: serverTrust),
                        systemTrusted: systemTrust.isTrusted,
                        host: normalizedHost,
                        policy: policy,
                        events: &events)
    }

    /// Evaluates a trust decision using a prepared certificate chain and policy.
    ///
    /// - Parameters:
    ///   - chain: The parsed certificate chain for the connection.
    ///   - systemTrusted: Whether system trust evaluation succeeded.
    ///   - host: The normalized hostname being evaluated.
    ///   - policy: The pinning policy to apply.
    ///   - events: The event log to append emitted events to.
    /// - Returns: The trust decision for the chain.
    func evaluate(chain: CertificateChain,
                  systemTrusted: Bool,
                  host: String,
                  policy: PinningPolicy,
                  events: inout [PinGuardEvent]) -> TrustDecision {
        dispatcher.emit(.chainSummary(host: host, summary: chain.summary), into: &events)
        guard !policy.pins.isEmpty else {
            dispatcher.emit(.pinSetEmpty(host: host), into: &events)
            return pinMismatchDecision(systemTrusted: systemTrusted, host: host, policy: policy, events: &events)
        }

        let matchedPins = pinMatcher.matchedPins(policy.pins, in: chain.candidates)
        guard matchedPins.isEmpty else {
            dispatcher.emit(.pinMatched(host: host, pins: matchedPins), into: &events)
            return TrustDecision(isTrusted: true, reason: .pinMatch, events: events)
        }

        return pinMismatchDecision(systemTrusted: systemTrusted, host: host, policy: policy, events: &events)
    }

    /// Decides whether a connection without a pin match may still proceed under the policy.
    ///
    /// - Parameters:
    ///   - systemTrusted: Whether system trust evaluation succeeded.
    ///   - host: The normalized hostname being evaluated.
    ///   - policy: The pinning policy to apply.
    ///   - events: The event log to append emitted events to.
    /// - Returns: The trust decision for the mismatch.
    private func pinMismatchDecision(systemTrusted: Bool,
                                     host: String,
                                     policy: PinningPolicy,
                                     events: inout [PinGuardEvent]) -> TrustDecision {
        if policy.allowSystemTrustFallback && systemTrusted {
            dispatcher.emit(.pinMismatchAllowedByFallback(host: host), into: &events)
            return TrustDecision(isTrusted: true, reason: .pinMismatchAllowedByFallback, events: events)
        }
        if policy.failStrategy == .permissive && systemTrusted {
            dispatcher.emit(.pinMismatchPermissive(host: host), into: &events)
            return TrustDecision(isTrusted: true, reason: .pinMismatchPermissive, events: events)
        }
        dispatcher.emit(.pinMismatch(host: host), into: &events)
        return TrustDecision(isTrusted: false, reason: .pinningFailed, events: events)
    }
}
