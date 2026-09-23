//
//  PinGuardTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import CryptoKit
import Foundation
@testable import PinGuard
import Testing

@Suite
struct PinGuardTests {

    private let host = "api.example.com"
    private let secret = Data("secret".utf8)

    private func policySet(hash: String) -> PolicySet {
        let policy = PinningPolicy(pins: [Pin(type: .spki, hash: hash)])
        return PolicySet(policies: [HostPolicy(pattern: .exact(host), policy: policy)])
    }

    private func signedBlob(policySet: PolicySet) throws -> RemoteConfigBlob {
        let payload = try JSONEncoder().encode(RemoteConfigPayload(policySet: policySet))
        let mac = HMAC<SHA256>.authenticationCode(for: payload, using: SymmetricKey(data: secret))
        return RemoteConfigBlob(payload: payload, signature: Data(mac), signatureType: .hmacSHA256(secretID: "id"))
    }

    @Test
    func startsWithEmptyProdConfiguration() async {
        let configuration = await PinGuard().currentConfiguration
        #expect(configuration.current == .prod)
        #expect(configuration.activePolicySet == PolicySet(policies: []))
    }

    @Test
    func configureReplacesConfiguration() async {
        let pinGuard = PinGuard()
        await pinGuard.configure { builder in
            builder.environment(.dev, policySet: policySet(hash: "dev"))
            builder.selectEnvironment(.dev)
            builder.systemLogging(false)
        }
        let configuration = await pinGuard.currentConfiguration
        #expect(configuration.current == .dev)
        #expect(configuration.activePolicySet == policySet(hash: "dev"))
        #expect(configuration.eventSinks.isEmpty)
    }

    @Test
    func evaluateUsesActiveEnvironment() async throws {
        let trust = try #require(TestCertificates.makeChainTrust())
        let sink = RecordingEventSink()
        var configuration = PinGuardConfiguration(eventSinks: [sink])
        configuration.environments[.dev] = PinGuardEnvironmentConfiguration(policySet: policySet(hash: "unknown"))
        configuration.environments[.prod] = PinGuardEnvironmentConfiguration(
            policySet: policySet(hash: TestCertificates.leafSPKIHash)
        )
        let pinGuard = PinGuard(configuration: configuration,
                                systemTrustEvaluator: FakeSystemTrustEvaluator(isTrusted: true))

        let prodDecision = await pinGuard.evaluate(serverTrust: trust, host: host)
        #expect(prodDecision.reason == .pinMatch)

        configuration.current = .dev
        await pinGuard.update(configuration: configuration)
        let devDecision = await pinGuard.evaluate(serverTrust: trust, host: host)
        #expect(devDecision.reason == .pinningFailed)
        #expect(sink.events.count == prodDecision.events.count + devDecision.events.count)
    }

    @Test
    func applyRemoteConfigReplacesPolicySetAndKeepsMTLS() async throws {
        let sink = RecordingEventSink()
        let mtls = MTLSConfiguration(provider: FakeClientCertificateProvider(result: .unavailable))
        var configuration = PinGuardConfiguration(eventSinks: [sink])
        configuration.environments[.prod] = PinGuardEnvironmentConfiguration(policySet: policySet(hash: "old"),
                                                                             mtlsConfiguration: mtls)
        let pinGuard = PinGuard(configuration: configuration)
        let verifier = HMACRemoteConfigVerifier { [secret] _ in secret }

        try await pinGuard.apply(remoteConfig: signedBlob(policySet: policySet(hash: "new")), verifier: verifier)

        let updated = await pinGuard.currentConfiguration
        #expect(updated.activePolicySet == policySet(hash: "new"))
        #expect(updated.activeMTLS != nil)
        #expect(sink.events == [.remoteConfigApplied(environment: "prod")])
    }

    @Test
    func applyRemoteConfigTargetsGivenEnvironment() async throws {
        let pinGuard = PinGuard(configuration: PinGuardConfiguration(eventSinks: []))
        let verifier = HMACRemoteConfigVerifier { [secret] _ in secret }
        try await pinGuard.apply(remoteConfig: signedBlob(policySet: policySet(hash: "uat")),
                                 verifier: verifier,
                                 to: .uat)
        let configuration = await pinGuard.currentConfiguration
        #expect(configuration.environments[.uat]?.policySet == policySet(hash: "uat"))
        #expect(configuration.current == .prod)
        #expect(configuration.activePolicySet == PolicySet(policies: []))
    }

    @Test
    func applyRemoteConfigRejectsBadSignatureWithoutChanges() async throws {
        let sink = RecordingEventSink()
        var configuration = PinGuardConfiguration(eventSinks: [sink])
        configuration.environments[.prod] = PinGuardEnvironmentConfiguration(policySet: policySet(hash: "old"))
        let pinGuard = PinGuard(configuration: configuration)
        let verifier = HMACRemoteConfigVerifier { _ in Data("wrong".utf8) }

        await #expect(throws: PinGuardError.invalidRemoteConfigSignature) {
            try await pinGuard.apply(remoteConfig: signedBlob(policySet: policySet(hash: "new")), verifier: verifier)
        }
        let unchanged = await pinGuard.currentConfiguration.activePolicySet
        #expect(unchanged == policySet(hash: "old"))
        #expect(sink.events.count == 1)
        guard case .remoteConfigRejected(let environment, _)? = sink.events.first else {
            Issue.record("Expected a remoteConfigRejected event")
            return
        }
        #expect(environment == "prod")
    }

    @Test
    func concurrentUpdatesLeaveOneOfThemActive() async {
        let pinGuard = PinGuard(configuration: PinGuardConfiguration(eventSinks: []))
        let hashes = (0..<100).map { "hash\($0)" }
        await withTaskGroup(of: Void.self) { group in
            for hash in hashes {
                group.addTask {
                    var configuration = PinGuardConfiguration(eventSinks: [])
                    let environment = PinGuardEnvironmentConfiguration(policySet: policySet(hash: hash))
                    configuration.environments[.prod] = environment
                    await pinGuard.update(configuration: configuration)
                }
            }
            for _ in 0..<100 {
                group.addTask {
                    _ = await pinGuard.currentConfiguration
                }
            }
        }
        let active = await pinGuard.currentConfiguration.activePolicySet.policies.first?.policy.pins.first?.hash
        #expect(active.map { hashes.contains($0) } == true)
    }

    @Test
    func sharedInstanceIsStable() {
        #expect(PinGuard.shared === PinGuard.shared)
    }
}
