//
//  CertificateChainTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

@testable import PinGuard
import Testing

@Suite
struct CertificateChainTests {

    @Test
    func leafAndRootReceiveTheirScopes() throws {
        let trust = try #require(TestCertificates.makeChainTrust())
        let chain = CertificateChain(trust: trust)
        #expect(chain.candidates.map(\.scope) == [.leaf, .root])
        #expect(chain.candidates.map(\.spkiHash) == [TestCertificates.leafSPKIHash, TestCertificates.rootSPKIHash])
        let certificateHashes = [TestCertificates.leafCertificateHash, TestCertificates.rootCertificateHash]
        #expect(chain.candidates.map(\.certificateHash) == certificateHashes)
    }

    @Test
    func threeCertificatesMarkTheMiddleAsIntermediate() throws {
        let trust = try #require(TestCertificates.makeThreeCertificateTrust())
        let chain = CertificateChain(trust: trust)
        #expect(chain.candidates.map(\.scope) == [.leaf, .intermediate, .root])
        #expect(chain.candidates[1].certificateHash == TestCertificates.intermediateCertificateHash)
        #expect(chain.summary.leafCommonName == "*.example.com")
        #expect(chain.summary.sanCount == 1)
    }

    @Test
    func singleCertificateIsLeaf() throws {
        let leaf = try #require(TestCertificates.leaf)
        let trust = try #require(TestCertificates.makeTrust(certificates: [leaf]))
        let chain = CertificateChain(trust: trust)
        #expect(chain.candidates.map(\.scope) == [.leaf])
        #expect(chain.summary.issuerCommonName == "*.example.com")
    }

    @Test
    func summaryRedactsNamesAndCountsSANs() throws {
        let trust = try #require(TestCertificates.makeChainTrust())
        let summary = CertificateChain(trust: trust).summary
        #expect(summary.leafCommonName == "*.example.com")
        #expect(summary.issuerCommonName == nil)
        #expect(summary.sanCount == TestCertificates.leafSANCount)
    }

    @Test
    func emptyCandidatesProduceEmptySummary() {
        let chain = CertificateChain(candidates: [])
        #expect(chain.summary == ChainSummary(leafCommonName: nil, issuerCommonName: nil, sanCount: 0))
    }
}
