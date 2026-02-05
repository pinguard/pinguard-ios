//
//  RemoteConfigVerificationTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 4.02.2026.
//

import XCTest
import CryptoKit
import Security
@testable import PinGuard

final class RemoteConfigVerificationTests: XCTestCase {

    // MARK: - HMAC Verification

    func testHMACVerificationSucceedsWithCorrectSecret() {
        let secret = Data("test-secret-key".utf8)
        let payload = Data("test-payload".utf8)

        let key = SymmetricKey(data: secret)
        let mac = HMAC<SHA256>.authenticationCode(for: payload, using: key)
        let signature = Data(mac)

        let blob = RemoteConfigBlob(
            payload: payload,
            signature: signature,
            signatureType: .hmacSHA256(secretID: "test-key-id")
        )

        let verifier = HMACRemoteConfigVerifier { secretID in
            guard secretID == "test-key-id" else { return nil }
            return secret
        }

        XCTAssertTrue(verifier.verify(blob: blob))
    }

    func testHMACVerificationFailsWithWrongSecret() {
        let correctSecret = Data("correct-secret".utf8)
        let wrongSecret = Data("wrong-secret".utf8)
        let payload = Data("test-payload".utf8)

        let key = SymmetricKey(data: correctSecret)
        let mac = HMAC<SHA256>.authenticationCode(for: payload, using: key)
        let signature = Data(mac)

        let blob = RemoteConfigBlob(
            payload: payload,
            signature: signature,
            signatureType: .hmacSHA256(secretID: "test-key-id")
        )

        let verifier = HMACRemoteConfigVerifier { _ in wrongSecret }

        XCTAssertFalse(verifier.verify(blob: blob))
    }

    func testHMACVerificationFailsWithWrongSignature() {
        let secret = Data("test-secret-key".utf8)
        let payload = Data("test-payload".utf8)
        let wrongSignature = Data("wrong-signature".utf8)

        let blob = RemoteConfigBlob(
            payload: payload,
            signature: wrongSignature,
            signatureType: .hmacSHA256(secretID: "test-key-id")
        )

        let verifier = HMACRemoteConfigVerifier { _ in secret }

        XCTAssertFalse(verifier.verify(blob: blob))
    }

    func testHMACVerificationFailsWhenSecretNotFound() {
        let payload = Data("test-payload".utf8)
        let signature = Data("any-signature".utf8)

        let blob = RemoteConfigBlob(
            payload: payload,
            signature: signature,
            signatureType: .hmacSHA256(secretID: "unknown-key-id")
        )

        let verifier = HMACRemoteConfigVerifier { _ in nil }

        XCTAssertFalse(verifier.verify(blob: blob))
    }

    func testHMACVerificationFailsForPublicKeySignatureType() {
        let secret = Data("test-secret-key".utf8)
        let payload = Data("test-payload".utf8)
        let signature = Data("signature".utf8)

        let blob = RemoteConfigBlob(
            payload: payload,
            signature: signature,
            signatureType: .publicKey(keyID: "key-id")
        )

        let verifier = HMACRemoteConfigVerifier { _ in secret }

        XCTAssertFalse(verifier.verify(blob: blob))
    }

    // MARK: - PublicKey Verification

    func testPublicKeyVerificationSucceedsWithValidSignature() throws {
        let privateKey = P256.Signing.PrivateKey()
        let payload = Data("test-payload".utf8)
        let signature = try privateKey.signature(for: payload)

        // Convert CryptoKit public key to SecKey
        let publicKeyData = privateKey.publicKey.x963Representation
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]

        guard let secKey = SecKeyCreateWithData(publicKeyData as CFData, attributes as CFDictionary, nil) else {
            XCTFail("Failed to create SecKey")
            return
        }

        let blob = RemoteConfigBlob(
            payload: payload,
            signature: signature.rawRepresentation,
            signatureType: .publicKey(keyID: "test-key-id")
        )

        let verifier = PublicKeyRemoteConfigVerifier { keyID in
            guard keyID == "test-key-id" else { return nil }
            return secKey
        }

        XCTAssertTrue(verifier.verify(blob: blob))
    }

    func testPublicKeyVerificationFailsWithWrongKey() throws {
        let privateKey1 = P256.Signing.PrivateKey()
        let privateKey2 = P256.Signing.PrivateKey()
        let payload = Data("test-payload".utf8)
        let signature = try privateKey1.signature(for: payload)

        // Use public key from different key pair
        let publicKeyData = privateKey2.publicKey.x963Representation
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]

        guard let secKey = SecKeyCreateWithData(publicKeyData as CFData, attributes as CFDictionary, nil) else {
            XCTFail("Failed to create SecKey")
            return
        }

        let blob = RemoteConfigBlob(
            payload: payload,
            signature: signature.rawRepresentation,
            signatureType: .publicKey(keyID: "test-key-id")
        )

        let verifier = PublicKeyRemoteConfigVerifier { _ in secKey }

        XCTAssertFalse(verifier.verify(blob: blob))
    }

    func testPublicKeyVerificationFailsWhenKeyNotFound() {
        let payload = Data("test-payload".utf8)
        let signature = Data("signature".utf8)

        let blob = RemoteConfigBlob(
            payload: payload,
            signature: signature,
            signatureType: .publicKey(keyID: "unknown-key-id")
        )

        let verifier = PublicKeyRemoteConfigVerifier { _ in nil }

        XCTAssertFalse(verifier.verify(blob: blob))
    }

    func testPublicKeyVerificationFailsForHMACSignatureType() throws {
        let privateKey = P256.Signing.PrivateKey()
        let payload = Data("test-payload".utf8)
        let publicKeyData = privateKey.publicKey.x963Representation

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]

        guard let secKey = SecKeyCreateWithData(publicKeyData as CFData, attributes as CFDictionary, nil) else {
            XCTFail("Failed to create SecKey")
            return
        }

        let blob = RemoteConfigBlob(
            payload: payload,
            signature: Data("signature".utf8),
            signatureType: .hmacSHA256(secretID: "secret-id")
        )

        let verifier = PublicKeyRemoteConfigVerifier { _ in secKey }

        XCTAssertFalse(verifier.verify(blob: blob))
    }

    // MARK: - RemoteConfigBlob

    func testRemoteConfigBlobEquality() {
        let blob1 = RemoteConfigBlob(
            payload: Data("payload".utf8),
            signature: Data("sig".utf8),
            signatureType: .hmacSHA256(secretID: "id")
        )

        let blob2 = RemoteConfigBlob(
            payload: Data("payload".utf8),
            signature: Data("sig".utf8),
            signatureType: .hmacSHA256(secretID: "id")
        )

        XCTAssertEqual(blob1, blob2)
    }

    func testRemoteConfigBlobInequality() {
        let blob1 = RemoteConfigBlob(
            payload: Data("payload1".utf8),
            signature: Data("sig".utf8),
            signatureType: .hmacSHA256(secretID: "id")
        )

        let blob2 = RemoteConfigBlob(
            payload: Data("payload2".utf8),
            signature: Data("sig".utf8),
            signatureType: .hmacSHA256(secretID: "id")
        )

        XCTAssertNotEqual(blob1, blob2)
    }

    // MARK: - RemoteConfigSignature

    func testRemoteConfigSignatureEquality() {
        let sig1 = RemoteConfigSignature.hmacSHA256(secretID: "id")
        let sig2 = RemoteConfigSignature.hmacSHA256(secretID: "id")

        XCTAssertEqual(sig1, sig2)
    }

    func testRemoteConfigSignatureInequality() {
        let sig1 = RemoteConfigSignature.hmacSHA256(secretID: "id1")
        let sig2 = RemoteConfigSignature.hmacSHA256(secretID: "id2")

        XCTAssertNotEqual(sig1, sig2)
    }
}
