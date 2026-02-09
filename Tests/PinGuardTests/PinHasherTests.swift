//
//  PinHasherTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 4.02.2026.
//

import CryptoKit
@testable import PinGuard
import Security
import XCTest

final class PinHasherTests: XCTestCase {

    // MARK: - RSA Key Hashing

    func testRSAKeyHashingProducesConsistentOutput() throws {
        let modulus = [UInt8](repeating: 0x01, count: 256)
        let exponent = [UInt8](repeating: 0x01, count: 3)
        let pkcs1 = asn1Sequence(asn1Integer(modulus) + asn1Integer(exponent))
        let keyData = Data(pkcs1)

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 2048
        ]

        guard let key = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, nil) else {
            XCTFail("Failed to create RSA key")
            return
        }

        let hash1 = try PinHasher.spkiHash(for: key)
        let hash2 = try PinHasher.spkiHash(for: key)

        XCTAssertEqual(hash1, hash2, "Hashing same key should produce identical output")
        XCTAssertFalse(hash1.isEmpty, "Hash should not be empty")
    }

    // MARK: - Helpers

    private func asn1Integer(_ bytes: [UInt8]) -> [UInt8] {
        var value = bytes
        if let first = value.first, first & 0x80 != 0 {
            value.insert(0x00, at: 0)
        }
        return [0x02] + lengthBytes(value.count) + value
    }

    private func asn1Sequence(_ content: [UInt8]) -> [UInt8] {
        [0x30] + lengthBytes(content.count) + content
    }

    private func lengthBytes(_ length: Int) -> [UInt8] {
        if length < 128 {
            return [UInt8(length)]
        }
        var len = length
        var bytes: [UInt8] = []
        while len > 0 {
            bytes.insert(UInt8(len & 0xff), at: 0)
            len >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    private func createSelfSignedCertificate() -> SecCertificate? {
        let privateKey = P256.Signing.PrivateKey()
        let publicKeyData = privateKey.publicKey.rawRepresentation

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]

        guard let secKey = SecKeyCreateWithData(publicKeyData as CFData, attributes as CFDictionary, nil) else {
            return nil
        }

        let certData = createMinimalCertificateData(publicKey: secKey)
        return SecCertificateCreateWithData(nil, certData as CFData)
    }

    private func createMinimalCertificateData(publicKey: SecKey) -> Data {
        let minimalDER: [UInt8] = [
            0x30, 0x82, 0x01, 0x00,
            0x30, 0x81, 0xF0
        ]
        return Data(minimalDER)
    }
}
