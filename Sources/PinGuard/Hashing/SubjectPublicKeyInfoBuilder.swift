//
//  SubjectPublicKeyInfoBuilder.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation
import Security

enum SubjectPublicKeyInfoBuilder {

    private static let rsaAlgorithmIdentifier: [UInt8] = [
        0x30, 0x0d, 0x06, 0x09,
        0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00
    ]

    private static let p256AlgorithmIdentifier: [UInt8] = [
        0x30, 0x13, 0x06, 0x07,
        0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x02, 0x01, 0x06,
        0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01,
        0x07
    ]

    private static let p384AlgorithmIdentifier: [UInt8] = [
        0x30, 0x10, 0x06, 0x07,
        0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x02, 0x01, 0x06,
        0x05, 0x2b, 0x81, 0x04,
        0x00, 0x22
    ]

    private static let p521AlgorithmIdentifier: [UInt8] = [
        0x30, 0x10, 0x06, 0x07,
        0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x02, 0x01, 0x06,
        0x05, 0x2b, 0x81, 0x04,
        0x00, 0x23
    ]

    /// Builds a DER SubjectPublicKeyInfo from the key type, size and raw public key bytes.
    ///
    /// - Parameters:
    ///   - keyType: The SecKey type identifier string (RSA or EC prime random).
    ///   - keySizeInBits: The key size used to select the EC curve identifier.
    ///   - keyBytes: The raw public key bytes as exported by Security.
    /// - Returns: The DER-encoded SubjectPublicKeyInfo.
    static func build(keyType: String, keySizeInBits: Int, keyBytes: Data) throws -> Data {
        let algorithmIdentifier = try algorithmIdentifier(keyType: keyType, keySizeInBits: keySizeInBits)
        let bitString = ASN1Encoder.bitString([UInt8](keyBytes))
        return Data(ASN1Encoder.sequence(algorithmIdentifier + bitString))
    }

    /// Selects the DER AlgorithmIdentifier for the given key type and size.
    ///
    /// - Parameters:
    ///   - keyType: The SecKey type identifier string.
    ///   - keySizeInBits: The key size used to select the EC curve identifier.
    /// - Returns: The DER-encoded AlgorithmIdentifier bytes.
    private static func algorithmIdentifier(keyType: String, keySizeInBits: Int) throws -> [UInt8] {
        if keyType == (kSecAttrKeyTypeRSA as String) {
            return rsaAlgorithmIdentifier
        }
        guard keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) else {
            throw PinGuardError.unsupportedKeyType
        }
        switch keySizeInBits {
        case 256:
            return p256AlgorithmIdentifier
        case 384:
            return p384AlgorithmIdentifier
        case 521:
            return p521AlgorithmIdentifier
        default:
            throw PinGuardError.unsupportedKeyType
        }
    }
}
