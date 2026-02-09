//
//  TrustEvaluator.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation
import Security

/// Evaluates server trust and certificate pins to produce a trust decision.
///
/// Resolves the pinning policy for a host, performs system trust evaluation,
/// compares the certificate chain against configured pins (SPKI, certificate, or CA),
/// and emits events throughout.
public final class TrustEvaluator {

    private let policyResolver: PolicyResolver
    private let eventSink: (@Sendable (PinGuardEvent) -> Void)?

    /// Creates a new trust evaluator configured with a policy set and optional event sink.
    ///
    /// - Parameters:
    ///   - policySet: The collection of host policies used to resolve pinning rules for a given host.
    ///   - eventSink: An optional closure that receives `PinGuardEvent` values emitted during evaluation
    ///                (useful for logging or analytics). If `nil`, events are only accumulated in results.
    public init(policySet: PolicySet,
                eventSink: (@Sendable (PinGuardEvent) -> Void)? = nil) {
        self.policyResolver = PolicyResolver(policySet: policySet)
        self.eventSink = eventSink
    }

    /// Evaluates the server trust and configured pins for the given host and returns a trust decision.
    ///
    /// - Parameters:
    ///   - serverTrust: The SecTrust object representing the server's certificate chain.
    ///   - host: The hostname to evaluate.
    public func evaluate(serverTrust: SecTrust,
                         host: String) -> TrustDecision {
        var events: [PinGuardEvent] = []
        let normalizedHost = HostPattern.normalizeHost(host)
        guard let policy = policyResolver.resolve(host: normalizedHost) else {
            let event = PinGuardEvent.policyMissing(host: normalizedHost)
            emit(event, into: &events)
            return TrustDecision(isTrusted: false, reason: .policyMissing, events: events)
        }

        let trustPolicy = SecPolicyCreateSSL(true, normalizedHost as CFString)
        SecTrustSetPolicies(serverTrust, trustPolicy)

        var trustError: CFError?
        let systemTrusted = SecTrustEvaluateWithError(serverTrust, &trustError)
        emit(.systemTrustEvaluated(host: normalizedHost, isTrusted: systemTrusted), into: &events)

        if policy.requireSystemTrust == true && systemTrusted == false {
            if policy.failStrategy == .permissive {
                emit(.systemTrustFailedPermissive(host: normalizedHost), into: &events)
                return TrustDecision(isTrusted: true, reason: .systemTrustFailedPermissive, events: events)
            }
            emit(.systemTrustFailed(host: normalizedHost, error: trustError?.localizedDescription), into: &events)
            return TrustDecision(isTrusted: false, reason: .trustFailed, events: events)
        }

        let chain = CertificateChain(trust: serverTrust)
        return evaluate(chain: chain,
                        systemTrusted: systemTrusted,
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
    func evaluate(chain: CertificateChain,
                  systemTrusted: Bool,
                  host: String,
                  policy: PinningPolicy,
                  events: inout [PinGuardEvent]) -> TrustDecision {
        emit(.chainSummary(host: host, summary: chain.summary), into: &events)
        let pinMatchResult = evaluatePins(policy: policy, chain: chain, host: host, events: &events)
        if pinMatchResult {
            return TrustDecision(isTrusted: true, reason: .pinMatch, events: events)
        }
        if policy.allowSystemTrustFallback && systemTrusted {
            emit(.pinMismatchAllowedByFallback(host: host), into: &events)
            return TrustDecision(isTrusted: true, reason: .pinMismatchAllowedByFallback, events: events)
        }
        if policy.failStrategy == .permissive && systemTrusted {
            emit(.pinMismatchPermissive(host: host), into: &events)
            return TrustDecision(isTrusted: true, reason: .pinMismatchPermissive, events: events)
        }
        emit(.pinMismatch(host: host), into: &events)
        return TrustDecision(isTrusted: false, reason: .pinningFailed, events: events)
    }

    /// Determines whether any configured pins match the provided certificate chain.
    ///
    /// - Parameters:
    ///   - policy: The pinning policy containing the pins to check.
    ///   - chain: The certificate chain candidates to test against.
    ///   - host: The hostname associated with this evaluation.
    ///   - events: The event log to append pinning events to.
    private func evaluatePins(policy: PinningPolicy,
                              chain: CertificateChain,
                              host: String,
                              events: inout [PinGuardEvent]) -> Bool {
        guard !policy.pins.isEmpty else {
            emit(.pinSetEmpty(host: host), into: &events)
            return false
        }

        let candidates = chain.candidates
        var matchedPins: [Pin] = []
        for pin in policy.pins where matches(pin: pin, candidates: candidates) {
            matchedPins.append(pin)
        }
        if matchedPins.isEmpty {
            return false
        }
        emit(.pinMatched(host: host, pins: matchedPins), into: &events)
        return true
    }

    /// Checks if the given pin matches any of the certificate candidates within scope.
    ///
    /// - Parameters:
    ///   - pin: The pin to test for a match.
    ///   - candidates: The candidate certificates derived from the chain.
    private func matches(pin: Pin, candidates: [CertificateCandidate]) -> Bool {
        for candidate in candidates where candidate.scope.contains(pin.scope) {
            switch pin.type {
            case .spki:
                if candidate.spkiHash == pin.hash {
                    return true
                }
            case .certificate:
                if candidate.certificateHash == pin.hash {
                    return true
                }
            case .ca:
                if candidate.scope.isCA, candidate.certificateHash == pin.hash {
                    return true
                }
            }
        }
        return false
    }

    /// Emits an event to the sink and records it in the running event list.
    ///
    /// - Parameters:
    ///   - event: The event to emit.
    ///   - events: The mutable list that accumulates emitted events.
    private func emit(_ event: PinGuardEvent, into events: inout [PinGuardEvent]) {
        events.append(event)
        eventSink?(event)
    }
}
