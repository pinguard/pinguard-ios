//
//  SubjectAlternativeNameCounter.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Foundation

enum SubjectAlternativeNameCounter {

    private static let extensionOID: [UInt8] = [0x06, 0x03, 0x55, 0x1D, 0x11]

    /// Scans DER-encoded certificate data and returns the largest SAN entry count found.
    ///
    /// - Parameter der: The DER-encoded certificate bytes.
    /// - Returns: The number of SAN entries, or zero when none can be parsed.
    static func count(in der: Data) -> Int {
        let bytes = [UInt8](der)
        var bestCount = 0
        var index = 0
        while index + extensionOID.count < bytes.count {
            if bytes[index..<(index + extensionOID.count)].elementsEqual(extensionOID),
               let count = parseEntryCount(in: bytes, oidStart: index) {
                bestCount = max(bestCount, count)
            }
            index += 1
        }
        return bestCount
    }

    /// Parses the SAN extension that starts at the given OID offset and returns its entry count.
    ///
    /// - Parameters:
    ///   - bytes: The DER-encoded certificate bytes.
    ///   - oidStart: The index at which the SAN OID begins.
    /// - Returns: The entry count, or `nil` when the structure is malformed.
    private static func parseEntryCount(in bytes: [UInt8], oidStart: Int) -> Int? {
        var index = oidStart + extensionOID.count
        guard skipOptionalBoolean(bytes, index: &index),
              let octet = readOctetString(bytes, index: &index),
              let sequence = readInnerSequence(bytes, octet: octet) else {
            return nil
        }

        return countSequenceEntries(bytes, range: sequence)
    }

    /// Skips an optional DER boolean if present at the current index.
    ///
    /// - Parameters:
    ///   - bytes: The DER-encoded data buffer.
    ///   - index: The current parsing index, advanced past the boolean if present.
    /// - Returns: `false` when the buffer ends unexpectedly.
    private static func skipOptionalBoolean(_ bytes: [UInt8], index: inout Int) -> Bool {
        guard index < bytes.count else {
            return false
        }

        guard bytes[index] == 0x01 else {
            return true
        }

        index += 1
        guard let (length, lengthBytes) = readLength(bytes, at: index) else {
            return false
        }

        index += lengthBytes + length
        return index < bytes.count
    }

    /// Reads an ASN.1 OCTET STRING and returns the range of its content.
    ///
    /// - Parameters:
    ///   - bytes: The DER-encoded data buffer.
    ///   - index: The current parsing index, advanced past the OCTET STRING on success.
    /// - Returns: The content range, or `nil` when no OCTET STRING is present.
    private static func readOctetString(_ bytes: [UInt8], index: inout Int) -> Range<Int>? {
        guard index < bytes.count, bytes[index] == 0x04 else {
            return nil
        }

        index += 1
        guard let (length, lengthBytes) = readLength(bytes, at: index) else {
            return nil
        }

        index += lengthBytes
        guard index + length <= bytes.count else {
            return nil
        }

        let range = index..<(index + length)
        index += length
        return range
    }

    /// Reads the ASN.1 SEQUENCE nested inside an OCTET STRING and returns the range of its content.
    ///
    /// - Parameters:
    ///   - bytes: The DER-encoded data buffer.
    ///   - octet: The content range of the enclosing OCTET STRING.
    /// - Returns: The sequence content range, or `nil` when the structure is malformed.
    private static func readInnerSequence(_ bytes: [UInt8], octet: Range<Int>) -> Range<Int>? {
        guard octet.count >= 2, bytes[octet.lowerBound] == 0x30 else {
            return nil
        }

        var index = octet.lowerBound + 1
        guard let (length, lengthBytes) = readLength(bytes, at: index) else {
            return nil
        }

        index += lengthBytes
        let end = index + length
        guard end <= octet.upperBound, end <= bytes.count else {
            return nil
        }

        return index..<end
    }

    /// Counts the number of TLV entries inside an ASN.1 SEQUENCE content range.
    ///
    /// - Parameters:
    ///   - bytes: The DER-encoded data buffer.
    ///   - range: The content range of the sequence.
    /// - Returns: The entry count, or `nil` when an entry overruns the range.
    private static func countSequenceEntries(_ bytes: [UInt8], range: Range<Int>) -> Int? {
        var index = range.lowerBound
        var count = 0
        while index < range.upperBound {
            index += 1
            guard let (length, lengthBytes) = readLength(bytes, at: index) else {
                return nil
            }

            index += lengthBytes + length
            guard index <= range.upperBound else {
                return nil
            }

            count += 1
        }
        return count
    }

    /// Reads a DER length field at the specified index.
    ///
    /// - Parameters:
    ///   - bytes: The DER-encoded data buffer.
    ///   - index: The index of the first length byte.
    /// - Returns: The decoded length and the number of bytes the length field occupies.
    private static func readLength(_ bytes: [UInt8], at index: Int) -> (length: Int, lengthBytes: Int)? {
        guard index < bytes.count else {
            return nil
        }

        let first = bytes[index]
        if first & 0x80 == 0 {
            return (Int(first), 1)
        }
        let count = Int(first & 0x7F)
        guard count > 0, count <= 4, index + count < bytes.count else {
            return nil
        }

        var value = 0
        for offset in 1...count {
            value = (value << 8) | Int(bytes[index + offset])
        }
        return (value, 1 + count)
    }
}
