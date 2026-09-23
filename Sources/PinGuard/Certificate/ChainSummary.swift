//
//  ChainSummary.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 10.02.2026.
//

public struct ChainSummary: Equatable, Sendable {

    public let leafCommonName: String?
    public let issuerCommonName: String?
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
