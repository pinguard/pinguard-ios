//
//  RemoteConfigVerifierTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 4.02.2026.
//

import CryptoKit
import Foundation
@testable import PinGuard
import Testing

@Suite
struct RemoteConfigVerifierTests {

    private let payload = Data("test-payload".utf8)
    private let secret = Data("test-secret-key".utf8)

    private func hmacBlob(secret: Data, secretID: String = "key-id") -> RemoteConfigBlob {
        let mac = HMAC<SHA256>.authenticationCode(for: payload, using: SymmetricKey(data: secret))
        return RemoteConfigBlob(payload: payload, signature: Data(mac), signatureType: .hmacSHA256(secretID: secretID))
    }

    @Test
    func hmacSucceedsWithCorrectSecret() {
        let verifier = HMACRemoteConfigVerifier { [secret] id in id == "key-id" ? secret : nil }
        let blob = hmacBlob(secret: secret)
        #expect(verifier.verify(blob: blob))
    }

    @Test
    func hmacFailsWithWrongSecretOrSignature() {
        let verifier = HMACRemoteConfigVerifier { [secret] _ in secret }
        let wrongSecretBlob = hmacBlob(secret: Data("other".utf8))
        #expect(!verifier.verify(blob: wrongSecretBlob))
        let tampered = RemoteConfigBlob(payload: payload,
                                        signature: Data("wrong".utf8),
                                        signatureType: .hmacSHA256(secretID: "key-id"))
        #expect(!verifier.verify(blob: tampered))
    }

    @Test
    func hmacFailsWhenSecretMissingOrTypeMismatches() {
        let missingSecret = HMACRemoteConfigVerifier { _ in nil }
        let blob = hmacBlob(secret: secret)
        #expect(!missingSecret.verify(blob: blob))
        let publicKeyBlob = RemoteConfigBlob(payload: payload,
                                             signature: Data(),
                                             signatureType: .publicKey(keyID: "key-id"))
        let verifier = HMACRemoteConfigVerifier { [secret] _ in secret }
        #expect(!verifier.verify(blob: publicKeyBlob))
    }

    @Test
    func publicKeyAcceptsRawAndDERSignatures() throws {
        let privateKey = P256.Signing.PrivateKey()
        let signature = try privateKey.signature(for: payload)
        let publicKeyData = privateKey.publicKey.x963Representation
        let verifier = PublicKeyRemoteConfigVerifier { id in id == "pk" ? publicKeyData : nil }
        for encoded in [signature.rawRepresentation, signature.derRepresentation] {
            let blob = RemoteConfigBlob(payload: payload, signature: encoded, signatureType: .publicKey(keyID: "pk"))
            #expect(verifier.verify(blob: blob))
        }
    }

    @Test
    func publicKeyRejectsWrongKeyTamperedPayloadAndMissingKey() throws {
        let signer = P256.Signing.PrivateKey()
        let signature = try signer.signature(for: payload).rawRepresentation
        let otherKeyData = P256.Signing.PrivateKey().publicKey.x963Representation
        let signerKeyData = signer.publicKey.x963Representation
        let blob = RemoteConfigBlob(payload: payload, signature: signature, signatureType: .publicKey(keyID: "pk"))
        let otherKeyVerifier = PublicKeyRemoteConfigVerifier { _ in otherKeyData }
        let missingKeyVerifier = PublicKeyRemoteConfigVerifier { _ in nil }
        let junkKeyVerifier = PublicKeyRemoteConfigVerifier { _ in Data("junk".utf8) }
        let signerVerifier = PublicKeyRemoteConfigVerifier { _ in signerKeyData }
        #expect(!otherKeyVerifier.verify(blob: blob))
        #expect(!missingKeyVerifier.verify(blob: blob))
        #expect(!junkKeyVerifier.verify(blob: blob))
        let tampered = RemoteConfigBlob(payload: Data("changed".utf8),
                                        signature: signature,
                                        signatureType: .publicKey(keyID: "pk"))
        #expect(!signerVerifier.verify(blob: tampered))
        let hmacTyped = hmacBlob(secret: secret)
        #expect(!signerVerifier.verify(blob: hmacTyped))
    }

    @Test
    func blobEqualityFollowsAllFields() {
        let first = hmacBlob(secret: secret)
        let same = hmacBlob(secret: secret)
        let other = hmacBlob(secret: secret, secretID: "other")
        #expect(first == same)
        #expect(first != other)
        #expect(RemoteConfigSignature.hmacSHA256(secretID: "a") != .hmacSHA256(secretID: "b"))
    }
}
