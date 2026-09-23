//
//  TrustEvaluatorTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

@testable import PinGuard
import Testing

@Suite
struct TrustEvaluatorTests {

    private let host = "api.example.com"
    private let leafPin = Pin(type: .spki, hash: TestCertificates.leafSPKIHash)
    private let unknownPin = Pin(type: .spki, hash: "unknown")

    private func evaluator(policy: PinningPolicy?,
                           systemTrusted: Bool,
                           sink: RecordingEventSink = RecordingEventSink()) -> TrustEvaluator {
        let policies = policy.map { [HostPolicy(pattern: .exact(host), policy: $0)] } ?? []
        return TrustEvaluator(policySet: PolicySet(policies: policies),
                              eventSinks: [sink],
                              systemTrustEvaluator: FakeSystemTrustEvaluator(isTrusted: systemTrusted,
                                                                             errorDescription: "expired"))
    }

    @Test
    func missingPolicyIsRejectedBeforeSystemTrust() async throws {
        let trust = try #require(TestCertificates.makeChainTrust())
        let decision = await evaluator(policy: nil, systemTrusted: true).evaluate(serverTrust: trust, host: host)
        #expect(decision == TrustDecision(isTrusted: false,
                                          reason: .policyMissing,
                                          events: [.policyMissing(host: host)]))
    }

    @Test
    func systemTrustFailureIsFatalUnderStrictPolicy() async throws {
        let trust = try #require(TestCertificates.makeChainTrust())
        let policy = PinningPolicy(pins: [leafPin], failStrategy: .strict)
        let decision = await evaluator(policy: policy, systemTrusted: false).evaluate(serverTrust: trust, host: host)
        #expect(decision.isTrusted == false)
        #expect(decision.reason == .trustFailed)
        #expect(decision.events == [.systemTrustEvaluated(host: host, isTrusted: false),
                                    .systemTrustFailed(host: host, error: "expired")])
    }

    @Test
    func systemTrustFailureIsAllowedUnderPermissivePolicy() async throws {
        let trust = try #require(TestCertificates.makeChainTrust())
        let policy = PinningPolicy(pins: [leafPin], failStrategy: .permissive)
        let decision = await evaluator(policy: policy, systemTrusted: false).evaluate(serverTrust: trust, host: host)
        #expect(decision.isTrusted)
        #expect(decision.reason == .systemTrustFailedPermissive)
        #expect(decision.events.last == .systemTrustFailedPermissive(host: host))
    }

    @Test
    func systemTrustFailureIsIgnoredWhenNotRequired() async throws {
        let trust = try #require(TestCertificates.makeChainTrust())
        let policy = PinningPolicy(pins: [leafPin], requireSystemTrust: false)
        let decision = await evaluator(policy: policy, systemTrusted: false).evaluate(serverTrust: trust, host: host)
        #expect(decision.reason == .pinMatch)
    }

    @Test
    func matchingPinIsTrustedAndEventsReachSink() async throws {
        let trust = try #require(TestCertificates.makeChainTrust())
        let sink = RecordingEventSink()
        let policy = PinningPolicy(pins: [unknownPin, leafPin])
        let decision = await evaluator(policy: policy, systemTrusted: true, sink: sink)
            .evaluate(serverTrust: trust, host: host)
        #expect(decision.isTrusted)
        #expect(decision.reason == .pinMatch)
        #expect(decision.events.last == .pinMatched(host: host, pins: [leafPin]))
        #expect(sink.events == decision.events)
    }

    @Test
    func mismatchUnderStrictPolicyIsRejected() async throws {
        let trust = try #require(TestCertificates.makeChainTrust())
        let policy = PinningPolicy(pins: [unknownPin], failStrategy: .strict)
        let decision = await evaluator(policy: policy, systemTrusted: true).evaluate(serverTrust: trust, host: host)
        #expect(decision.isTrusted == false)
        #expect(decision.reason == .pinningFailed)
        #expect(decision.events.last == .pinMismatch(host: host))
    }

    @Test
    func mismatchWithFallbackIsAllowedWhenSystemTrusted() async throws {
        let trust = try #require(TestCertificates.makeChainTrust())
        let policy = PinningPolicy(pins: [unknownPin], allowSystemTrustFallback: true)
        let decision = await evaluator(policy: policy, systemTrusted: true).evaluate(serverTrust: trust, host: host)
        #expect(decision.reason == .pinMismatchAllowedByFallback)
        #expect(decision.events.last == .pinMismatchAllowedByFallback(host: host))
    }

    @Test
    func mismatchUnderPermissivePolicyIsAllowedWhenSystemTrusted() async throws {
        let trust = try #require(TestCertificates.makeChainTrust())
        let policy = PinningPolicy(pins: [unknownPin], failStrategy: .permissive)
        let decision = await evaluator(policy: policy, systemTrusted: true).evaluate(serverTrust: trust, host: host)
        #expect(decision.reason == .pinMismatchPermissive)
    }

    @Test
    func fallbackNeedsSystemTrust() async throws {
        let trust = try #require(TestCertificates.makeChainTrust())
        let policy = PinningPolicy(pins: [unknownPin],
                                   failStrategy: .permissive,
                                   requireSystemTrust: false,
                                   allowSystemTrustFallback: true)
        let decision = await evaluator(policy: policy, systemTrusted: false).evaluate(serverTrust: trust, host: host)
        #expect(decision.reason == .pinningFailed)
    }

    @Test
    func emptyPinSetEmitsEventAndFollowsMismatchRules() async throws {
        let trust = try #require(TestCertificates.makeChainTrust())
        let strict = PinningPolicy(pins: [])
        let strictDecision = await evaluator(policy: strict, systemTrusted: true)
            .evaluate(serverTrust: trust, host: host)
        #expect(strictDecision.reason == .pinningFailed)
        #expect(strictDecision.events.contains(.pinSetEmpty(host: host)))

        let fallback = PinningPolicy(pins: [], allowSystemTrustFallback: true)
        let fallbackDecision = await evaluator(policy: fallback, systemTrusted: true)
            .evaluate(serverTrust: trust, host: host)
        #expect(fallbackDecision.reason == .pinMismatchAllowedByFallback)
    }

    @Test
    func hostIsNormalizedBeforeResolution() async throws {
        let trust = try #require(TestCertificates.makeChainTrust())
        let decision = await evaluator(policy: PinningPolicy(pins: [leafPin]), systemTrusted: true)
            .evaluate(serverTrust: trust, host: "API.EXAMPLE.COM.")
        #expect(decision.reason == .pinMatch)
        #expect(decision.events.first == .systemTrustEvaluated(host: host, isTrusted: true))
    }

    @Test
    func realSystemEvaluatorRejectsSelfSignedChain() async throws {
        let trust = try #require(TestCertificates.makeChainTrust())
        let evaluator = TrustEvaluator(policySet: PolicySet(policies: [
            HostPolicy(pattern: .exact(host), policy: PinningPolicy(pins: [leafPin]))
        ]))
        let decision = await evaluator.evaluate(serverTrust: trust, host: host)
        #expect(decision.reason == .trustFailed)
        guard case .systemTrustFailed(_, let error)? = decision.events.last else {
            Issue.record("Expected a systemTrustFailed event, got \(decision.events)")
            return
        }
        #expect(error?.isEmpty == false)
    }
}
