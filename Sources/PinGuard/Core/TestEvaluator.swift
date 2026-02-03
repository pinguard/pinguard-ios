import Foundation
import Security

public final class TrustEvaluator {
    private let policyResolver: PolicyResolver
    private let eventSink: ((PinGuardEvent) -> Void)?

    public init(policySet: PolicySet, eventSink: ((PinGuardEvent) -> Void)? = nil) {
        self.policyResolver = PolicyResolver(policySet: policySet)
        self.eventSink = eventSink
    }

    public func evaluate(serverTrust: SecTrust, host: String) -> TrustDecision {
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
        return evaluate(
            chain: chain,
            systemTrusted: systemTrusted,
            host: normalizedHost,
            policy: policy,
            events: &events
        )
    }

    func evaluate(
        chain: CertificateChain,
        systemTrusted: Bool,
        host: String,
        policy: PinningPolicy,
        events: inout [PinGuardEvent]
    ) -> TrustDecision {
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

    private func evaluatePins(policy: PinningPolicy, chain: CertificateChain, host: String, events: inout [PinGuardEvent]) -> Bool {
        guard !policy.pins.isEmpty else {
            emit(.pinSetEmpty(host: host), into: &events)
            return false
        }
        let candidates = chain.candidates
        var matchedPins: [Pin] = []
        for pin in policy.pins {
            if matches(pin: pin, candidates: candidates) {
                matchedPins.append(pin)
            }
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
                if candidate.spkiHash == pin.hash { return true }
            case .certificate:
                if candidate.certificateHash == pin.hash { return true }
            case .ca:
                if candidate.scope.isCA, candidate.certificateHash == pin.hash { return true }
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
        self.summary = ChainSummary(candidates: items)
    }

    init(candidates: [CertificateCandidate]) {
        self.candidates = candidates
        self.summary = ChainSummary(candidates: candidates)
    }
}

struct CertificateCandidate {
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

    init(candidates: [CertificateCandidate]) {
        guard let leaf = candidates.first else {
            self.leafCommonName = nil
            self.issuerCommonName = nil
            self.sanCount = 0
            return
        }
        let leafCert = leaf.certificate
        self.leafCommonName = CertificateSummary.safeCommonName(leafCert)
        self.issuerCommonName = CertificateSummary.safeIssuerCommonName(leafCert)
        self.sanCount = CertificateSummary.subjectAlternativeNameCount(leafCert)
    }
}

enum CertificateSummary {
    static func safeCommonName(_ cert: SecCertificate) -> String? {
        guard let summary = SecCertificateCopySubjectSummary(cert) else { return nil }
        let commonName: String = summary as String
        return redactDomain(commonName)
    }

    static func safeIssuerCommonName(_ cert: SecCertificate) -> String? {
#if canImport(Security)
        // SecCertificateCopyValues and kSecOIDX509V1IssuerName are not available in all SDKs.
        // Prefer using the subject summary of the issuer certificate when available.
        // Since we only have the leaf certificate here, we cannot traverse to the issuer
        // without a trust object. Fall back to using the certificate's subject summary
        // (redacted) as an approximation, otherwise return nil.
        if let summary = SecCertificateCopySubjectSummary(cert) {
            let commonName: String = summary as String
            return redactDomain(commonName)
        }
#endif
        return nil
    }

    static func subjectAlternativeNameCount(_ cert: SecCertificate) -> Int {
        // SecCertificateCopyValues and kSecOIDSubjectAltName are not guaranteed to be available.
        // Without parsing ASN.1, conservatively return 0 when we cannot query SANs.
        _ = cert // keep parameter used
        return 0
    }

    private static func redactDomain(_ value: String) -> String? {
        let normalized = value.lowercased()
        let labels = normalized.split(separator: ".")
        guard labels.count >= 2 else { return nil }
        return "*." + labels.suffix(2).joined(separator: ".")
    }
}

