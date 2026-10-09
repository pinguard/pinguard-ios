//
//  ChainSummary.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 10.02.2026.
//

/// A redacted description of a certificate chain that is safe to log.
public struct ChainSummary: Equatable, Sendable {

    /// The leaf subject reduced to `*.example.com` form, or `nil` when it is not domain-like.
    public let leafCommonName: String?

    /// The issuer subject reduced to `*.example.com` form, or `nil` when it is not domain-like.
    public let issuerCommonName: String?

    /// The number of Subject Alternative Name entries on the leaf certificate.
    public let sanCount: Int

    public init(leafCommonName: String?,
                issuerCommonName: String?,
                sanCount: Int) {
        self.leafCommonName = leafCommonName
        self.issuerCommonName = issuerCommonName
        self.sanCount = sanCount
    }

    init(candidates: [CertificateCandidate]) {
        guard let leaf = candidates.first else {
            self.leafCommonName = nil
            self.issuerCommonName = nil
            self.sanCount = 0
            return
        }

        let issuer = candidates.dropFirst().first ?? leaf
        self.leafCommonName = CertificateSummaryReader.redactedSubjectName(of: leaf.certificate)
        self.issuerCommonName = CertificateSummaryReader.redactedSubjectName(of: issuer.certificate)
        self.sanCount = CertificateSummaryReader.subjectAlternativeNameCount(of: leaf.certificate)
    }
}
