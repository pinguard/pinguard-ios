//
//  PinHasher.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import CryptoKit
import Foundation
import Security

public enum PinHasher {

    /// Computes a Base64-encoded SHA-256 hash of the key's Subject Public Key Info (SPKI).
    ///
    /// - Parameter key: The SecKey whose SPKI will be hashed.
    /// - Returns: The Base64-encoded digest.
    public static func spkiHash(for key: SecKey) throws -> String {
        guard let keyData = SecKeyCopyExternalRepresentation(key, nil) as Data? else {
            throw PinGuardError.unsupportedKeyType
        }
        let attributes = SecKeyCopyAttributes(key) as NSDictionary? ?? [:]
        guard let keyType = attributes[kSecAttrKeyType] as? String else {
            throw PinGuardError.unsupportedKeyType
        }
        let keySize = attributes[kSecAttrKeySizeInBits] as? Int ?? 0
        let spki = try SubjectPublicKeyInfoBuilder.build(keyType: keyType,
                                                         keySizeInBits: keySize,
                                                         keyBytes: keyData)
        return sha256Base64(spki)
    }

    /// Computes a Base64-encoded SHA-256 hash of the certificate's DER data.
    ///
    /// - Parameter certificate: The certificate to hash.
    /// - Returns: The Base64-encoded digest.
    public static func certificateHash(for certificate: SecCertificate) -> String {
        let data = SecCertificateCopyData(certificate) as Data
        return sha256Base64(data)
    }

    /// Computes the Base64-encoded SHA-256 digest of the provided data.
    ///
    /// - Parameter data: The raw bytes to hash.
    /// - Returns: The Base64-encoded digest.
    private static func sha256Base64(_ data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return Data(digest).base64EncodedString()
    }
}
