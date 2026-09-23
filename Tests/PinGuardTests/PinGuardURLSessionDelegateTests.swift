//
//  PinGuardURLSessionDelegateTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Foundation
@testable import PinGuard
import Testing

@Suite
struct PinGuardURLSessionDelegateTests {

    private let host = "api.example.com"

    private func respond(_ delegate: PinGuardURLSessionDelegate,
                         to method: String) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        let space = URLProtectionSpace(host: host,
                                       port: 443,
                                       protocol: "https",
                                       realm: nil,
                                       authenticationMethod: method)
        let challenge = URLAuthenticationChallenge(protectionSpace: space,
                                                   proposedCredential: nil,
                                                   previousFailureCount: 0,
                                                   failureResponse: nil,
                                                   error: nil,
                                                   sender: NoopChallengeSender())
        return await delegate.urlSession(.shared, didReceive: challenge)
    }

    private func pinGuard(mtls: MTLSConfiguration?, sink: RecordingEventSink) -> PinGuard {
        var configuration = PinGuardConfiguration(eventSinks: [sink])
        configuration.environments[.prod] = PinGuardEnvironmentConfiguration(policySet: PolicySet(policies: []),
                                                                             mtlsConfiguration: mtls)
        return PinGuard(configuration: configuration)
    }

    @Test
    func unknownMethodsUseDefaultHandling() async {
        let delegate = PinGuardURLSessionDelegate(pinGuard: pinGuard(mtls: nil, sink: RecordingEventSink()))
        let (disposition, credential) = await respond(delegate, to: NSURLAuthenticationMethodHTTPBasic)
        #expect(disposition == .performDefaultHandling)
        #expect(credential == nil)
    }

    @Test
    func serverTrustWithoutTrustObjectIsCancelled() async {
        let delegate = PinGuardURLSessionDelegate(pinGuard: pinGuard(mtls: nil, sink: RecordingEventSink()))
        let (disposition, _) = await respond(delegate, to: NSURLAuthenticationMethodServerTrust)
        #expect(disposition == .cancelAuthenticationChallenge)
    }

    @Test
    func clientCertificateWithoutMTLSRejectsProtectionSpace() async {
        let sink = RecordingEventSink()
        let delegate = PinGuardURLSessionDelegate(pinGuard: pinGuard(mtls: nil, sink: sink))
        let (disposition, _) = await respond(delegate, to: NSURLAuthenticationMethodClientCertificate)
        #expect(disposition == .rejectProtectionSpace)
        #expect(sink.events.isEmpty)
    }

    @Test
    func unavailableIdentityEmitsMissingEvent() async {
        let sink = RecordingEventSink()
        let mtls = MTLSConfiguration(provider: FakeClientCertificateProvider(result: .unavailable))
        let delegate = PinGuardURLSessionDelegate(pinGuard: pinGuard(mtls: mtls, sink: sink))
        let (disposition, _) = await respond(delegate, to: NSURLAuthenticationMethodClientCertificate)
        #expect(disposition == .rejectProtectionSpace)
        #expect(sink.events == [.mtlsIdentityMissing(host: host)])
    }

    @Test
    func renewalRequiredInvokesCallback() async {
        let sink = RecordingEventSink()
        let counter = CallCounter()
        let mtls = MTLSConfiguration(provider: FakeClientCertificateProvider(result: .renewalRequired)) {
            counter.increment()
        }
        let delegate = PinGuardURLSessionDelegate(pinGuard: pinGuard(mtls: mtls, sink: sink))
        let (disposition, _) = await respond(delegate, to: NSURLAuthenticationMethodClientCertificate)
        #expect(disposition == .rejectProtectionSpace)
        #expect(counter.count == 1)
        #expect(sink.events == [.mtlsIdentityMissing(host: host)])
    }

    @Test
    func mtlsIsResolvedFromCurrentConfigurationPerChallenge() async {
        let sink = RecordingEventSink()
        let pinGuard = pinGuard(mtls: nil, sink: sink)
        let delegate = PinGuardURLSessionDelegate(pinGuard: pinGuard)
        let (before, _) = await respond(delegate, to: NSURLAuthenticationMethodClientCertificate)
        #expect(sink.events.isEmpty)
        #expect(before == .rejectProtectionSpace)

        var configuration = await pinGuard.currentConfiguration
        let mtls = MTLSConfiguration(provider: FakeClientCertificateProvider(result: .unavailable))
        configuration.environments[.prod] = PinGuardEnvironmentConfiguration(policySet: PolicySet(policies: []),
                                                                             mtlsConfiguration: mtls)
        await pinGuard.update(configuration: configuration)
        _ = await respond(delegate, to: NSURLAuthenticationMethodClientCertificate)
        #expect(sink.events == [.mtlsIdentityMissing(host: host)])
    }
}
