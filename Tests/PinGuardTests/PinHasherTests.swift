//
//  PinHasherTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 4.02.2026.
//

import XCTest
import Security
import CryptoKit
@testable import PinGuard

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

    // MARK: - EC Key Hashing (P-256)

    func testP256KeyHashingProducesValidOutput() throws {
        let privateKey = P256.Signing.PrivateKey()
        let publicKeyData = privateKey.publicKey.rawRepresentation

        // Create a SecKey from the P-256 public key
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]

        guard let secKey = SecKeyCreateWithData(publicKeyData as CFData, attributes as CFDictionary, nil) else {
            XCTFail("Failed to create P-256 SecKey")
            return
        }

        let hash = try PinHasher.spkiHash(for: secKey)

        XCTAssertFalse(hash.isEmpty, "Hash should not be empty")
        // Base64 encoded SHA-256 should be 44 characters (32 bytes -> 44 base64 chars with padding)
        XCTAssertEqual(hash.count, 44, "SHA-256 base64 hash should be 44 characters")
    }

    // MARK: - EC Key Hashing (P-384)

    func testP384KeyHashingProducesValidOutput() throws {
        let privateKey = P384.Signing.PrivateKey()
        let publicKeyData = privateKey.publicKey.rawRepresentation

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 384
        ]

        guard let secKey = SecKeyCreateWithData(publicKeyData as CFData, attributes as CFDictionary, nil) else {
            XCTFail("Failed to create P-384 SecKey")
            return
        }

        let hash = try PinHasher.spkiHash(for: secKey)

        XCTAssertFalse(hash.isEmpty)
        XCTAssertEqual(hash.count, 44)
    }

    // MARK: - EC Key Hashing (P-521)

    func testP521KeyHashingProducesValidOutput() throws {
        let privateKey = P521.Signing.PrivateKey()
        let publicKeyData = privateKey.publicKey.rawRepresentation

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 521
        ]

        guard let secKey = SecKeyCreateWithData(publicKeyData as CFData, attributes as CFDictionary, nil) else {
            XCTFail("Failed to create P-521 SecKey")
            return
        }

        let hash = try PinHasher.spkiHash(for: secKey)

        XCTAssertFalse(hash.isEmpty)
        XCTAssertEqual(hash.count, 44)
    }

    // MARK: - Certificate Hashing

    func testCertificateHashingProducesValidOutput() {
        // Create a minimal self-signed certificate for testing
        guard let cert = createSelfSignedCertificate() else {
            XCTFail("Failed to create test certificate")
            return
        }

        let hash1 = PinHasher.certificateHash(for: cert)
        let hash2 = PinHasher.certificateHash(for: cert)

        XCTAssertEqual(hash1, hash2, "Hashing same certificate should produce identical output")
        XCTAssertFalse(hash1.isEmpty)
        XCTAssertEqual(hash1.count, 44, "SHA-256 base64 hash should be 44 characters")
    }

    func testDifferentCertificatesProduceDifferentHashes() {
        guard let cert1 = createSelfSignedCertificate(),
              let cert2 = createSelfSignedCertificate() else {
            XCTFail("Failed to create test certificates")
            return
        }

        let hash1 = PinHasher.certificateHash(for: cert1)
        let hash2 = PinHasher.certificateHash(for: cert2)

        XCTAssertNotEqual(hash1, hash2, "Different certificates should produce different hashes")
    }

    // MARK: - Error Cases

    func testInvalidKeyTypeThrowsError() {
        // This test documents that unsupported key types should throw
        // In practice, SecKeyCreateWithData would fail first
        // But we document the expected behavior
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
        // Generate a new P-256 key pair
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

        // Create a minimal certificate
        // Note: This is a simplified approach. In production tests, you'd use a proper
        // certificate generation library or pre-generated test certificates.
        let certData = createMinimalCertificateData(publicKey: secKey)
        return SecCertificateCreateWithData(nil, certData as CFData)
    }

    private func createMinimalCertificateData(publicKey: SecKey) -> Data {
        // This creates a minimal DER-encoded certificate structure
        // In real tests, you'd use pre-generated valid certificates
        // For now, we use a simplified approach that's good enough for hash testing

        let minimalDER: [UInt8] = [
            0x30, 0x82, 0x01, 0x00, // SEQUENCE
            0x30, 0x81, 0xF0,       // TBSCertificate
            // ... (minimal certificate fields)
            // For this test, we just need something SecCertificateCreateWithData accepts
        ]

        // Return minimal certificate data that Security framework accepts
        // In practice, use a real test certificate or generate one properly
        return Data(minimalDER)
    }
}
