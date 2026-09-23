//
//  RSAPublicKeyFixture.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Foundation
import Security

enum RSAPublicKeyFixture {

    static let expectedSPKIHash = "Y7EKzelfzqmyMnNRDIX8cecAf6wj1nk7nT25ws/qnVo="

    /// Creates the fixture key from a fixed modulus and exponent.
    ///
    /// - Returns: The public key, or `nil` when Security rejects the encoding.
    static func makeKey() -> SecKey? {
        let modulus = [UInt8](repeating: 0x01, count: 256)
        let exponent = [UInt8](repeating: 0x01, count: 3)
        let pkcs1 = sequence(integer(modulus) + integer(exponent))
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 2048
        ]
        return SecKeyCreateWithData(Data(pkcs1) as CFData, attributes as CFDictionary, nil)
    }

    /// Encodes bytes as a DER INTEGER.
    ///
    /// - Parameter bytes: The big-endian magnitude bytes.
    /// - Returns: The encoded INTEGER.
    private static func integer(_ bytes: [UInt8]) -> [UInt8] {
        var value = bytes
        if let first = value.first, first & 0x80 != 0 {
            value.insert(0x00, at: 0)
        }
        return [0x02] + length(value.count) + value
    }

    /// Encodes content as a DER SEQUENCE.
    ///
    /// - Parameter content: The sequence contents.
    /// - Returns: The encoded SEQUENCE.
    private static func sequence(_ content: [UInt8]) -> [UInt8] {
        [0x30] + length(content.count) + content
    }

    /// Encodes a DER length.
    ///
    /// - Parameter value: The length to encode.
    /// - Returns: The encoded length bytes.
    private static func length(_ value: Int) -> [UInt8] {
        if value < 128 {
            return [UInt8(value)]
        }
        var remaining = value
        var bytes: [UInt8] = []
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xff), at: 0)
            remaining >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }
}
