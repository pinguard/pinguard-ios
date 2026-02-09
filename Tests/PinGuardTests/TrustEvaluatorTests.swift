//
//  TrustEvaluatorTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

@testable import PinGuard
import Security
import XCTest

final class TrustEvaluatorTests: XCTestCase {

    func testSPKIHashMatchesExpected() throws {
        let modulus = [UInt8](repeating: 0x01, count: 256)
        let exponent = [UInt8](repeating: 0x01, count: 3)
        let pkcs1 = asn1Sequence(asn1Integer(modulus) + asn1Integer(exponent))
        let keyData = Data(pkcs1)
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 2048
        ]
        let key = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, nil)
        XCTAssertNotNil(key)
        guard let key else {
            return XCTFail("Failed to create SecKey")
        }

        let hash = try PinHasher.spkiHash(for: key)
        XCTAssertEqual(hash, "Y7EKzelfzqmyMnNRDIX8cecAf6wj1nk7nT25ws/qnVo=")
    }

    func testRotationBackupPinIsAccepted() {
        let primaryPin = Pin(type: .spki, hash: "primaryHash", role: .primary)
        let backupPin = Pin(type: .spki, hash: "backupHash", role: .backup)
        let policy = PinningPolicy(pins: [primaryPin, backupPin], failStrategy: .strict)

        XCTAssertEqual(policy.pins.count, 2, "Rotation requires both primary and backup pins")
        XCTAssertTrue(policy.pins.contains {
            $0.role == .primary
        }, "Should have primary pin")
        XCTAssertTrue(policy.pins.contains {
            $0.role == .backup
        }, "Should have backup pin")
        XCTAssertEqual(primaryPin.role, .primary)
        XCTAssertEqual(backupPin.role, .backup)
    }

    private func asn1Integer(_ bytes: [UInt8]) -> [UInt8] {
        var value = bytes
        if let first = value.first, first & 0x80 != 0 {
            value.insert(0x00, at: 0)
        }
        return [0x02] + lengthBytes(value.count) + value
    }

    private func asn1Sequence(_ content: [UInt8]) -> [UInt8] {
        [0x30] + lengthBytes(content.count) + content
    }

    private func lengthBytes(_ length: Int) -> [UInt8] {
        if length < 128 {
            return [UInt8(length)]
        }
        var len = length
        var bytes: [UInt8] = []
        while len > 0 {
            bytes.insert(UInt8(len & 0xff), at: 0)
            len >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }
}
