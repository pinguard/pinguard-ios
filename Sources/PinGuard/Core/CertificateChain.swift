//
//  CertificateChain.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 10.02.2026.
//

import Foundation
import Security

struct CertificateChain {

    let candidates: [CertificateCandidate]
    let summary: ChainSummary

    init(trust: SecTrust) {
        var items: [CertificateCandidate] = []
        if let certChain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] {
            let count = certChain.count
            for (index, cert) in certChain.enumerated() {
                let scope: CertificateScope
                if index == 0 {
                    scope = .leaf
                } else if index == count - 1 {
                    scope = .root
                } else {
                    scope = .intermediate
                }
                let candidate = CertificateCandidate(certificate: cert, scope: scope)
                items.append(candidate)
            }
        }
        self.candidates = items
        self.summary = ChainSummary(candidates: items, trust: trust)
    }

    init(candidates: [CertificateCandidate],
         trust: SecTrust) {
        self.candidates = candidates
        self.summary = ChainSummary(candidates: candidates, trust: trust)
    }
}

/// A computed representation of a certificate used for pin matching.
///
/// `CertificateCandidate` wraps a `SecCertificate` with precomputed values needed during
/// evaluation, including the Base64-encoded SHA-256 hashes of the certificate (DER) and
/// its Subject Public Key Info (SPKI), along with the certificate's scope in the chain
/// (leaf, intermediate, or root).
public struct CertificateCandidate {

    let certificate: SecCertificate
    let spkiHash: String
    let certificateHash: String
    let scope: CertificateScope

    init(certificate: SecCertificate, scope: CertificateScope) {
        self.certificate = certificate
        self.scope = scope
        self.certificateHash = PinHasher.certificateHash(for: certificate)
        if let key = SecCertificateCopyKey(certificate) {
            self.spkiHash = (try? PinHasher.spkiHash(for: key)) ?? ""
        } else {
            self.spkiHash = ""
        }
    }
}

enum CertificateScope: String {

    /// The end-entity (leaf) certificate.
    case leaf

    /// An intermediate CA certificate.
    case intermediate

    /// The root CA certificate.
    case root

    var isCA: Bool { self != .leaf }

    /// Returns whether the certificate scope contains the given pin scope.
    ///
    /// - Parameter scope: The pin scope to test for inclusion.
    func contains(_ scope: PinScope) -> Bool {
        switch scope {
        case .any:
            return true
        case .leaf:
            return self == .leaf
        case .intermediate:
            return self == .intermediate
        case .root:
            return self == .root
        }
    }
}

public struct ChainSummary: Equatable, Sendable {

    public let leafCommonName: String?
    public let issuerCommonName: String?
    public let sanCount: Int

    public init(candidates: [CertificateCandidate],
                trust: SecTrust?) {
        guard let leaf = candidates.first else {
            self.leafCommonName = nil
            self.issuerCommonName = nil
            self.sanCount = 0
            return
        }

        let leafCert = leaf.certificate
        self.leafCommonName = CertificateSummary.safeCommonName(leafCert)
        self.issuerCommonName = CertificateSummary.safeIssuerCommonName(leafCert,
                                                                        trust: trust)
        self.sanCount = CertificateSummary.subjectAlternativeNameCount(leafCert)
    }
}

private enum CertificateSummary {

    /// Returns a redacted subject common name for the certificate, if available.
    ///
    /// - Parameter cert: The certificate whose subject common name will be read.
    static func safeCommonName(_ cert: SecCertificate) -> String? {
        guard let summary = SecCertificateCopySubjectSummary(cert) else {
            return nil
        }

        let commonName: String = summary as String
        return redactDomain(commonName)
    }

    /// Returns a redacted issuer common name for the certificate chain, if available.
    ///
    /// - Parameters:
    ///   - leafCert: The leaf certificate for which to determine the issuer.
    ///   - trust: The trust object that may contain the issuer chain.
    static func safeIssuerCommonName(_ leafCert: SecCertificate, trust: SecTrust?) -> String? {
#if canImport(Security)
        if let trust,
           let issuerCert = issuerCertificate(from: trust, leaf: leafCert),
           let issuerSummary = SecCertificateCopySubjectSummary(issuerCert) {
            return redactDomain(issuerSummary as String)
        }

        if let summary = SecCertificateCopySubjectSummary(leafCert) {
            return redactDomain(summary as String)
        }
        return nil
#else
        _ = leafCert; _ = trust
        return nil
#endif
    }

    /// Returns the number of Subject Alternative Name entries present in the certificate.
    ///
    /// - Parameter cert: The certificate to inspect.
    static func subjectAlternativeNameCount(_ cert: SecCertificate) -> Int {
#if canImport(Security)
        let der = SecCertificateCopyData(cert) as Data
        return countSANEntries(in: der)
#else
        _ = cert
        return 0
#endif
    }

#if canImport(Security)
    /// Attempts to locate the issuer certificate in the trust chain for the given leaf.
    ///
    /// - Parameters:
    ///   - trust: The trust object containing the evaluated chain.
    ///   - leaf: The leaf certificate whose issuer is sought.
    private static func issuerCertificate(from trust: SecTrust, leaf: SecCertificate) -> SecCertificate? {
        let certs = SecTrustCopyCertificateChain(trust) as? [SecCertificate] ?? []
        guard certs.count >= 2 else {
            return nil
        }

        let leafData = SecCertificateCopyData(leaf) as Data
        if let idx = certs.firstIndex(where: { (SecCertificateCopyData($0) as Data) == leafData }) {
            let issuerIdx = idx + 1
            return issuerIdx < certs.count ? certs[issuerIdx] : nil
        }

        return certs[1]
    }
#endif

    /// Redacts a domain-like string to a wildcard form of its registrable suffix (e.g., *.example.com).
    ///
    /// - Parameter value: The input string to redact.
    private static func redactDomain(_ value: String) -> String? {
        let normalized = value.lowercased()
        let labels = normalized.split(separator: ".")
        guard labels.count >= 2 else {
            return nil
        }

        return "*." + labels.suffix(2).joined(separator: ".")
    }

#if canImport(Security)
    /// Scans DER-encoded certificate data to count Subject Alternative Name entries.
    ///
    /// - Parameter der: The DER-encoded certificate bytes.
    private static func countSANEntries(in der: Data) -> Int {
        let oid: [UInt8] = [0x06, 0x03, 0x55, 0x1D, 0x11]
        let bytes = [UInt8](der)

        var bestCount = 0
        var i = 0
        while i + oid.count < bytes.count {
            if bytes[i..<(i + oid.count)].elementsEqual(oid) {
                if let count = tryParseSANCount(from: bytes, oidStart: i) {
                    bestCount = max(bestCount, count)
                }
            }
            i += 1
        }
        return bestCount
    }

    /// Attempts to parse a SAN extension sequence starting at the given OID offset and return the number of entries.
    ///
    /// - Parameters:
    ///   - bytes: The DER-encoded certificate bytes.
    ///   - oidStart: The index at which the SAN OID begins.
    private static func tryParseSANCount(from bytes: [UInt8], oidStart: Int) -> Int? {
        var idx = oidStart + 5

        guard skipOptionalBoolean(bytes, idx: &idx) else {
            return nil
        }

        guard let octet = readOctetString(bytes, at: &idx) else {
            return nil
        }

        guard let seq = readInnerSequence(bytes, octet: octet) else {
            return nil
        }

        return countSequenceEntries(bytes, start: seq.start, end: seq.end)
    }

    /// Skips an optional DER boolean if present at the current index.
    ///
    /// - Parameters:
    ///   - bytes: The DER-encoded data buffer.
    ///   - idx: The current parsing index, advanced past the boolean if present.
    private static func skipOptionalBoolean(_ bytes: [UInt8], idx: inout Int) -> Bool {
        guard idx < bytes.count else {
            return false
        }

        guard bytes[idx] == 0x01 else {
            return true
        }

        idx += 1
        guard let (len, lenBytes) = readDERLength(bytes, at: idx) else {
            return false
        }

        idx += lenBytes + len
        return idx < bytes.count
    }

    private struct OctetRange {

        let start: Int
        let length: Int
    }

    /// Reads an ASN.1 OCTET STRING and returns its byte range.
    ///
    /// - Parameters:
    ///   - bytes: The DER-encoded data buffer.
    ///   - idx: The current parsing index; advanced past the OCTET STRING on success.
    private static func readOctetString(_ bytes: [UInt8], at idx: inout Int) -> OctetRange? {
        guard idx < bytes.count, bytes[idx] == 0x04 else {
            return nil
        }

        idx += 1

        guard let (octetLen, octetLenBytes) = readDERLength(bytes, at: idx) else {
            return nil
        }

        idx += octetLenBytes

        guard idx + octetLen <= bytes.count else {
            return nil
        }

        let range = OctetRange(start: idx, length: octetLen)
        idx += octetLen
        return range
    }

    private struct SequenceRange {

        let start: Int
        let end: Int
    }

    /// Reads an ASN.1 OCTET STRING and returns its byte range.
    ///
    /// - Parameters:
    ///   - bytes: The DER-encoded data buffer.
    ///   - idx: The current parsing index; advanced past the OCTET STRING on success.
    private static func readInnerSequence(_ bytes: [UInt8], octet: OctetRange) -> SequenceRange? {
        let innerStart = octet.start

        guard octet.length >= 2, innerStart < bytes.count, bytes[innerStart] == 0x30 else {
            return nil
        }

        var innerIdx = innerStart + 1
        guard let (seqLen, seqLenBytes) = readDERLength(bytes, at: innerIdx) else {
            return nil
        }

        innerIdx += seqLenBytes
        let seqEnd = innerIdx + seqLen

        guard seqEnd <= innerStart + octet.length, seqEnd <= bytes.count else {
            return nil
        }

        return SequenceRange(start: innerIdx, end: seqEnd)
    }

    /// Counts the number of entries in an ASN.1 SEQUENCE between the given bounds.
    ///
    /// - Parameters:
    ///   - bytes: The DER-encoded data buffer.
    ///   - start: The index of the first byte inside the sequence content.
    ///   - end: The index one past the last byte of the sequence content.
    private static func countSequenceEntries(_ bytes: [UInt8], start: Int, end: Int) -> Int? {
        var innerIdx = start
        var count = 0

        while innerIdx < end {
            innerIdx += 1
            guard let (len, lenBytes) = readDERLength(bytes, at: innerIdx) else {
                return nil
            }

            innerIdx += lenBytes + len
            guard innerIdx <= end else {
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
    private static func readDERLength(_ bytes: [UInt8], at index: Int) -> (len: Int, lenBytes: Int)? {
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
        for i in 0..<count {
            value = (value << 8) | Int(bytes[index + 1 + i])
        }
        return (value, 1 + count)
    }
#endif
}
