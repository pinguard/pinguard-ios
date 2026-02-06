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

    /// Evaluates the server trust and configured pins for the given host and returns a trust decision.
    ///
    /// - Parameters:
    ///   - serverTrust: The SecTrust object representing the server's certificate chain.
    ///   - host: The hostname to evaluate.
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

    /// Evaluates a trust decision using a prepared certificate chain and policy.
    ///
    /// - Parameters:
    ///   - chain: The parsed certificate chain for the connection.
    ///   - systemTrusted: Whether system trust evaluation succeeded.
    ///   - host: The normalized hostname being evaluated.
    ///   - policy: The pinning policy to apply.
    ///   - events: The event log to append emitted events to.
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

    /// Determines whether any configured pins match the provided certificate chain.
    ///
    /// - Parameters:
    ///   - policy: The pinning policy containing the pins to check.
    ///   - chain: The certificate chain candidates to test against.
    ///   - host: The hostname associated with this evaluation.
    ///   - events: The event log to append pinning events to.
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

    /// Checks if the given pin matches any of the certificate candidates within scope.
    ///
    /// - Parameters:
    ///   - pin: The pin to test for a match.
    ///   - candidates: The candidate certificates derived from the chain.
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

    /// Emits an event to the sink and records it in the running event list.
    ///
    /// - Parameters:
    ///   - event: The event to emit.
    ///   - events: The mutable list that accumulates emitted events.
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
