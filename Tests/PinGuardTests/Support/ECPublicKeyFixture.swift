//
//  ECPublicKeyFixture.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import CryptoKit
import Foundation
import Security

enum ECPublicKeyFixture {

    /// Creates a Security key from a CryptoKit P-256 public key.
    ///
    /// - Parameter publicKey: The CryptoKit key to convert.
    /// - Returns: The Security key, or `nil` when the conversion fails.
    static func makeSecKey(from publicKey: P256.Signing.PublicKey) -> SecKey? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        return SecKeyCreateWithData(publicKey.x963Representation as CFData, attributes as CFDictionary, nil)
    }

    /// Computes the Base64 SHA-256 of the key's DER SubjectPublicKeyInfo using CryptoKit only.
    ///
    /// - Parameter publicKey: The CryptoKit key to hash.
    /// - Returns: The expected SPKI pin hash.
    static func expectedSPKIHash(of publicKey: P256.Signing.PublicKey) -> String {
        Data(SHA256.hash(data: publicKey.derRepresentation)).base64EncodedString()
    }
}
