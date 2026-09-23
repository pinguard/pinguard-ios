//
//  SubjectAlternativeNameCounterTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Foundation
@testable import PinGuard
import Testing

@Suite
struct SubjectAlternativeNameCounterTests {

    @Test
    func countsEntriesOfLeafCertificate() {
        #expect(SubjectAlternativeNameCounter.count(in: TestCertificates.leafDER) == TestCertificates.leafSANCount)
    }

    @Test
    func returnsZeroWithoutExtension() {
        #expect(SubjectAlternativeNameCounter.count(in: TestCertificates.rootDER) == 0)
    }

    @Test
    func returnsZeroForGarbage() {
        #expect(SubjectAlternativeNameCounter.count(in: Data(repeating: 0x55, count: 64)) == 0)
        #expect(SubjectAlternativeNameCounter.count(in: Data()) == 0)
    }

    @Test
    func truncatedExtensionDoesNotCrash() {
        let truncated = TestCertificates.leafDER.prefix(TestCertificates.leafDER.count - 40)
        _ = SubjectAlternativeNameCounter.count(in: Data(truncated))
    }
}
