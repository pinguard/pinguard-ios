//
//  ASN1Encoder.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

enum ASN1Encoder {

    /// Encodes the given content as an ASN.1 SEQUENCE using DER length encoding.
    ///
    /// - Parameter content: The sequence contents to be wrapped.
    /// - Returns: The encoded SEQUENCE bytes.
    static func sequence(_ content: [UInt8]) -> [UInt8] {
        [0x30] + lengthBytes(content.count) + content
    }

    /// Encodes the given content as an ASN.1 BIT STRING with zero unused bits.
    ///
    /// - Parameter content: The bit string payload.
    /// - Returns: The encoded BIT STRING bytes.
    static func bitString(_ content: [UInt8]) -> [UInt8] {
        [0x03] + lengthBytes(content.count + 1) + [0x00] + content
    }

    /// Encodes a length value using ASN.1 DER length rules.
    ///
    /// - Parameter length: The length to encode.
    /// - Returns: The encoded length bytes.
    private static func lengthBytes(_ length: Int) -> [UInt8] {
        if length < 128 {
            return [UInt8(length)]
        }
        var remaining = length
        var bytes: [UInt8] = []
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xff), at: 0)
            remaining >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }
}
