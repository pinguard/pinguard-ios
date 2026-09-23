//
//  ASN1EncoderTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

@testable import PinGuard
import Testing

@Suite
struct ASN1EncoderTests {

    @Test
    func shortFormLengthIsSingleByte() {
        #expect(ASN1Encoder.sequence([0x01, 0x02]) == [0x30, 0x02, 0x01, 0x02])
    }

    @Test
    func longFormLengthUsesLengthOfLengthPrefix() {
        let content = [UInt8](repeating: 0xAA, count: 300)
        let encoded = ASN1Encoder.sequence(content)
        #expect(Array(encoded.prefix(4)) == [0x30, 0x82, 0x01, 0x2C])
        #expect(encoded.count == 4 + content.count)
    }

    @Test
    func bitStringPrependsZeroUnusedBits() {
        #expect(ASN1Encoder.bitString([0xFF]) == [0x03, 0x02, 0x00, 0xFF])
    }
}
