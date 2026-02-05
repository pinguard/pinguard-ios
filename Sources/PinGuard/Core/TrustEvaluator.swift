//
//  TrustEvaluator.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation
import Security

public final class TrustEvaluator {

    private let policyResolver: PolicyResolver
    private let eventSink: (@Sendable (PinGuardEvent) -> Void)?

    public init(policySet: PolicySet,
                eventSink: (@Sendable (PinGuardEvent) -> Void)? = nil) {
        self.policyResolver = PolicyResolver(policySet: policySet)
        self.eventSink = eventSink
    }

    public func evaluate(serverTrust: SecTrust,
                         host: String) -> TrustDecision {
        var events: [PinGuardEvent] = []
        let normalizedHost = HostPattern.normalizeHost(host)
        guard let policy = policyResolver.resolve(host: normalizedHost) else {
            let event = PinGuardEvent.policyMissing(host: normalizedHost)
            emit(event, into: &events)
            return TrustDecision(isTrusted: false, reason: .policyMissing, events: events)
        }

        let trustPolicy = SecPolicyCreateSSL(true, normalizedHost as CFString)
        SecTrustSetPolicies(serverTrust, trustPolicy)

        var trustError: CFError?
        let systemTrusted = SecTrustEvaluateWithError(serverTrust, &trustError)
        emit(.systemTrustEvaluated(host: normalizedHost, isTrusted: systemTrusted), into: &events)

        if policy.requireSystemTrust == true && systemTrusted == false {
            if policy.failStrategy == .permissive {
                emit(.systemTrustFailedPermissive(host: normalizedHost), into: &events)
                return TrustDecision(isTrusted: true, reason: .systemTrustFailedPermissive, events: events)
            }
            emit(.systemTrustFailed(host: normalizedHost, error: trustError?.localizedDescription), into: &events)
            return TrustDecision(isTrusted: false, reason: .trustFailed, events: events)
        }

        let chain = CertificateChain(trust: serverTrust)
        return evaluate(chain: chain,
                        systemTrusted: systemTrusted,
                        host: normalizedHost,
                        policy: policy,
                        events: &events)
    }

    func evaluate(chain: CertificateChain,
                  systemTrusted: Bool,
                  host: String,
                  policy: PinningPolicy,
                  events: inout [PinGuardEvent]) -> TrustDecision {
        emit(.chainSummary(host: host, summary: chain.summary), into: &events)
        let pinMatchResult = evaluatePins(policy: policy, chain: chain, host: host, events: &events)
        if pinMatchResult {
            return TrustDecision(isTrusted: true, reason: .pinMatch, events: events)
        }
        if policy.allowSystemTrustFallback && systemTrusted {
            emit(.pinMismatchAllowedByFallback(host: host), into: &events)
            return TrustDecision(isTrusted: true, reason: .pinMismatchAllowedByFallback, events: events)
        }
        if policy.failStrategy == .permissive && systemTrusted {
            emit(.pinMismatchPermissive(host: host), into: &events)
            return TrustDecision(isTrusted: true, reason: .pinMismatchPermissive, events: events)
        }
        emit(.pinMismatch(host: host), into: &events)
        return TrustDecision(isTrusted: false, reason: .pinningFailed, events: events)
    }

    private func evaluatePins(policy: PinningPolicy,
                              chain: CertificateChain,
                              host: String,
                              events: inout [PinGuardEvent]) -> Bool {
        guard !policy.pins.isEmpty else {
            emit(.pinSetEmpty(host: host), into: &events)
            return false
        }

        let candidates = chain.candidates
        var matchedPins: [Pin] = []
        for pin in policy.pins where matches(pin: pin, candidates: candidates) {
            matchedPins.append(pin)
        }
        if matchedPins.isEmpty {
            return false
        }
        emit(.pinMatched(host: host, pins: matchedPins), into: &events)
        return true
    }

    private func matches(pin: Pin, candidates: [CertificateCandidate]) -> Bool {
        for candidate in candidates where candidate.scope.contains(pin.scope) {
            switch pin.type {
            case .spki:
                if candidate.spkiHash == pin.hash {
                    return true
                }
            case .certificate:
                if candidate.certificateHash == pin.hash {
                    return true
                }
            case .ca:
                if candidate.scope.isCA, candidate.certificateHash == pin.hash {
                    return true
                }
            }
        }
        return false
    }

    private func emit(_ event: PinGuardEvent, into events: inout [PinGuardEvent]) {
        events.append(event)
        eventSink?(event)
    }
}

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
    case leaf
    case intermediate
    case root

    var isCA: Bool { self != .leaf }

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

    static func safeCommonName(_ cert: SecCertificate) -> String? {
        guard let summary = SecCertificateCopySubjectSummary(cert) else {
            return nil
        }

        let commonName: String = summary as String
        return redactDomain(commonName)
    }

    static func safeIssuerCommonName(_ leafCert: SecCertificate, trust: SecTrust?) -> String? {
#if canImport(Security)
        if let trust,
           let issuerCert = issuerCertificate(from: trust, leaf: leafCert),
           let issuerSummary = SecCertificateCopySubjectSummary(issuerCert) {
            return redactDomain(issuerSummary as String)
        }

        // fallback (approx): leaf'in subject summary'si (issuer değil!)
        if let summary = SecCertificateCopySubjectSummary(leafCert) {
            return redactDomain(summary as String)
        }
        return nil
#else
        _ = leafCert; _ = trust
        return nil
#endif
    }

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


    private static func redactDomain(_ value: String) -> String? {
        let normalized = value.lowercased()
        let labels = normalized.split(separator: ".")
        guard labels.count >= 2 else {
            return nil
        }

        return "*." + labels.suffix(2).joined(separator: ".")
    }

#if canImport(Security)
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

private static func tryParseSANCount(from bytes: [UInt8], oidStart: Int) -> Int? {
    var idx = oidStart
    idx += 5

    if idx < bytes.count, bytes[idx] == 0x01 {
        idx += 1
        guard let (len, lenBytes) = readDERLength(bytes, at: idx) else {
            return nil
        }

        idx += lenBytes + len
        if idx >= bytes.count {
            return nil
        }
    }

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

    let innerStart = idx
    guard octetLen >= 2, bytes[innerStart] == 0x30 else {
        return nil
    }

    var innerIdx = innerStart + 1
    guard let (seqLen, seqLenBytes) = readDERLength(bytes, at: innerIdx) else {
        return nil
    }

    innerIdx += seqLenBytes

    let seqEnd = innerIdx + seqLen
    guard seqEnd <= innerStart + octetLen, seqEnd <= bytes.count else {
        return nil
    }

    var count = 0
    while innerIdx < seqEnd {
        innerIdx += 1
        guard let (len, lenBytes) = readDERLength(bytes, at: innerIdx) else {
            return nil
        }

        innerIdx += lenBytes + len
        if innerIdx <= seqEnd { count += 1 } else {
            return nil
        }
    }

    return count
}

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
