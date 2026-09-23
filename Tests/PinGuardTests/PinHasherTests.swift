//
//  PinHasherTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 4.02.2026.
//

import CryptoKit
import Foundation
@testable import PinGuard
import Security
import Testing

@Suite
struct PinHasherTests {

    @Test
    func rsaSPKIHashMatchesKnownValue() throws {
        let key = try #require(RSAPublicKeyFixture.makeKey())
        #expect(try PinHasher.spkiHash(for: key) == RSAPublicKeyFixture.expectedSPKIHash)
    }

    @Test
    func ecSPKIHashMatchesCryptoKitDERRepresentation() throws {
        let publicKey = P256.Signing.PrivateKey().publicKey
        let key = try #require(ECPublicKeyFixture.makeSecKey(from: publicKey))
        #expect(try PinHasher.spkiHash(for: key) == ECPublicKeyFixture.expectedSPKIHash(of: publicKey))
    }

    @Test
    func certificateSPKIHashMatchesOpenSSL() throws {
        let leaf = try #require(TestCertificates.leaf)
        let key = try #require(SecCertificateCopyKey(leaf))
        #expect(try PinHasher.spkiHash(for: key) == TestCertificates.leafSPKIHash)
    }

    @Test
    func certificateHashMatchesOpenSSL() throws {
        let leaf = try #require(TestCertificates.leaf)
        let root = try #require(TestCertificates.root)
        #expect(PinHasher.certificateHash(for: leaf) == TestCertificates.leafCertificateHash)
        #expect(PinHasher.certificateHash(for: root) == TestCertificates.rootCertificateHash)
    }

    @Test
    func hashingIsDeterministic() throws {
        let key = try #require(RSAPublicKeyFixture.makeKey())
        #expect(try PinHasher.spkiHash(for: key) == PinHasher.spkiHash(for: key))
    }
}
