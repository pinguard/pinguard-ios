//
//  PinGuardBuilderTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

@testable import PinGuard
import Testing

@Suite
struct PinGuardBuilderTests {

    private let policySet = PolicySet(policies: [
        HostPolicy(pattern: .exact("api.example.com"), policy: PinningPolicy(pins: [Pin(type: .spki, hash: "a")]))
    ])

    @Test
    func buildsEnvironmentsAndSelection() {
        var builder = PinGuardBuilder()
        builder.environment(.dev, policySet: PolicySet(policies: []))
        builder.environment(.prod, policySet: policySet)
        builder.selectEnvironment(.prod)
        let configuration = builder.build()
        #expect(configuration.environments.count == 2)
        #expect(configuration.current == .prod)
        #expect(configuration.activePolicySet == policySet)
        #expect(configuration.activeMTLS == nil)
    }

    @Test
    func defaultsToProdWithSystemLogging() {
        let configuration = PinGuardBuilder().build()
        #expect(configuration.current == .prod)
        #expect(configuration.activePolicySet == PolicySet(policies: []))
        #expect(configuration.eventSinks.count == 1)
        #expect(configuration.eventSinks.first is OSLogEventSink)
    }

    @Test
    func systemLoggingCanBeDisabled() {
        var builder = PinGuardBuilder()
        builder.systemLogging(false)
        #expect(builder.build().eventSinks.isEmpty)
    }

    @Test
    func customSinksFollowSystemLogging() {
        var builder = PinGuardBuilder()
        let sink = RecordingEventSink()
        builder.addEventSink(sink)
        builder.telemetry { _ in }
        let sinks = builder.build().eventSinks
        #expect(sinks.count == 3)
        #expect(sinks[0] is OSLogEventSink)
        #expect(sinks[1] is RecordingEventSink)
        #expect(sinks[2] is ClosureEventSink)
    }

    @Test
    func mtlsIsStoredPerEnvironment() {
        var builder = PinGuardBuilder()
        let provider = FakeClientCertificateProvider(result: .unavailable)
        builder.environment(.prod, policySet: policySet, mtls: MTLSConfiguration(provider: provider))
        builder.environment(.dev, policySet: policySet)
        builder.selectEnvironment(.prod)
        #expect(builder.build().activeMTLS != nil)
        builder.selectEnvironment(.dev)
        #expect(builder.build().activeMTLS == nil)
    }
}
