//
//  SubjectPublicKeyInfoBuilderTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Foundation
@testable import PinGuard
import Security
import Testing

@Suite
struct SubjectPublicKeyInfoBuilderTests {

    private let keyBytes = Data(repeating: 0x04, count: 65)

    @Test(arguments: [256, 384, 521])
    func supportedCurveSizesProduceSequence(size: Int) throws {
        let spki = try SubjectPublicKeyInfoBuilder.build(keyType: kSecAttrKeyTypeECSECPrimeRandom as String,
                                                         keySizeInBits: size,
                                                         keyBytes: keyBytes)
        #expect(spki.first == 0x30)
        #expect(spki.count > keyBytes.count)
    }

    @Test(arguments: [0, 192, 224, 512])
    func unsupportedCurveSizeThrows(size: Int) {
        #expect(throws: PinGuardError.unsupportedKeyType) {
            try SubjectPublicKeyInfoBuilder.build(keyType: kSecAttrKeyTypeECSECPrimeRandom as String,
                                                  keySizeInBits: size,
                                                  keyBytes: keyBytes)
        }
    }

    @Test
    func unknownKeyTypeThrows() {
        #expect(throws: PinGuardError.unsupportedKeyType) {
            try SubjectPublicKeyInfoBuilder.build(keyType: "bogus", keySizeInBits: 2048, keyBytes: keyBytes)
        }
    }

    @Test
    func rsaIgnoresKeySize() throws {
        let spki = try SubjectPublicKeyInfoBuilder.build(keyType: kSecAttrKeyTypeRSA as String,
                                                         keySizeInBits: 0,
                                                         keyBytes: keyBytes)
        #expect(spki.first == 0x30)
    }
}
