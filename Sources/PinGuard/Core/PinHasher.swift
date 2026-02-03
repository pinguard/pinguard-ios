import Foundation
import CryptoKit
import Security

public enum PinHasher {
    public static func spkiHash(for key: SecKey) throws -> String {
        guard let keyData = SecKeyCopyExternalRepresentation(key, nil) as Data? else {
            throw PinGuardError.unsupportedKeyType
        }
        let attributes = SecKeyCopyAttributes(key) as NSDictionary? ?? [:]
        guard let keyType = attributes[kSecAttrKeyType] as? String else {
            throw PinGuardError.unsupportedKeyType
        }
        let spki = try SubjectPublicKeyInfoBuilder.buildSPKI(keyType: keyType, attributes: attributes, keyBytes: keyData)
        return sha256Base64(spki)
    }

    public static func certificateHash(for certificate: SecCertificate) -> String {
        let data = SecCertificateCopyData(certificate) as Data
        return sha256Base64(data)
    }

    private static func sha256Base64(_ data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return Data(digest).base64EncodedString()
    }
}

enum SubjectPublicKeyInfoBuilder {
    static func buildSPKI(keyType: String, attributes: NSDictionary, keyBytes: Data) throws -> Data {
        let algorithmIdentifier: [UInt8]
        if keyType == (kSecAttrKeyTypeRSA as String) {
            algorithmIdentifier = [
                0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
            ]
        } else if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            let size = attributes[kSecAttrKeySizeInBits] as? Int ?? 0
            switch size {
            case 256:
                algorithmIdentifier = [
                    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
                ]
            case 384:
                algorithmIdentifier = [
                    0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22
                ]
            case 521:
                algorithmIdentifier = [
                    0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23
                ]
            default:
                throw PinGuardError.unsupportedKeyType
            }
        } else {
            throw PinGuardError.unsupportedKeyType
        }

        let bitString = ASN1.bitString([UInt8](keyBytes))
        let spkiBody = algorithmIdentifier + bitString
        return Data(ASN1.sequence(spkiBody))
    }
}

enum ASN1 {
    static func sequence(_ content: [UInt8]) -> [UInt8] {
        [0x30] + lengthBytes(content.count) + content
    }

    static func bitString(_ content: [UInt8]) -> [UInt8] {
        [0x03] + lengthBytes(content.count + 1) + [0x00] + content
    }

    private static func lengthBytes(_ length: Int) -> [UInt8] {
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
