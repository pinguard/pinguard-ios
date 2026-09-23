//
//  PinMatcherTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

@testable import PinGuard
import Testing

@Suite
struct PinMatcherTests {

    private let matcher = PinMatcher()

    private func candidates() throws -> [CertificateCandidate] {
        let trust = try #require(TestCertificates.makeChainTrust())
        return CertificateChain(trust: trust).candidates
    }

    @Test
    func spkiPinMatchesLeaf() throws {
        let pin = Pin(type: .spki, hash: TestCertificates.leafSPKIHash, scope: .leaf)
        #expect(try matcher.matchedPins([pin], in: candidates()) == [pin])
    }

    @Test
    func spkiPinScopedToRootDoesNotMatchLeaf() throws {
        let pin = Pin(type: .spki, hash: TestCertificates.leafSPKIHash, scope: .root)
        #expect(try matcher.matchedPins([pin], in: candidates()).isEmpty)
    }

    @Test
    func certificatePinMatchesAnyPosition() throws {
        let pin = Pin(type: .certificate, hash: TestCertificates.rootCertificateHash)
        #expect(try matcher.matchedPins([pin], in: candidates()) == [pin])
    }

    @Test
    func caPinMatchesRootButNotLeaf() throws {
        let rootPin = Pin(type: .ca, hash: TestCertificates.rootCertificateHash)
        let leafPin = Pin(type: .ca, hash: TestCertificates.leafCertificateHash)
        #expect(try matcher.matchedPins([rootPin, leafPin], in: candidates()) == [rootPin])
    }

    @Test
    func intermediateScopedPinsMatchOnlyTheMiddleCertificate() throws {
        let trust = try #require(TestCertificates.makeThreeCertificateTrust())
        let candidates = CertificateChain(trust: trust).candidates
        let intermediatePin = Pin(type: .spki, hash: TestCertificates.intermediateSPKIHash, scope: .intermediate)
        let caPin = Pin(type: .ca, hash: TestCertificates.intermediateCertificateHash, scope: .intermediate)
        let misplacedPin = Pin(type: .ca, hash: TestCertificates.intermediateCertificateHash, scope: .root)
        #expect(matcher.matchedPins([intermediatePin, caPin, misplacedPin], in: candidates) == [intermediatePin, caPin])
    }

    @Test
    func returnsEveryMatchedPinIncludingBackup() throws {
        let primary = Pin(type: .spki, hash: "unknown", role: .primary)
        let backup = Pin(type: .spki, hash: TestCertificates.leafSPKIHash, role: .backup)
        #expect(try matcher.matchedPins([primary, backup], in: candidates()) == [backup])
    }
}
