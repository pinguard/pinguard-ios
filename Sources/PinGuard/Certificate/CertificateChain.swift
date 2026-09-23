//
//  CertificateChain.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 10.02.2026.
//

import Security

struct CertificateChain {

    let candidates: [CertificateCandidate]
    let summary: ChainSummary

    init(trust: SecTrust) {
        let certificates = SecTrustCopyCertificateChain(trust) as? [SecCertificate] ?? []
        let lastIndex = certificates.count - 1
        let items = certificates.enumerated().map { index, certificate in
            let scope: CertificateScope
            if index == 0 {
                scope = .leaf
            } else if index == lastIndex {
                scope = .root
            } else {
                scope = .intermediate
            }
            return CertificateCandidate(certificate: certificate, scope: scope)
        }
        self.candidates = items
        self.summary = ChainSummary(candidates: items)
    }

    init(candidates: [CertificateCandidate]) {
        self.candidates = candidates
        self.summary = ChainSummary(candidates: candidates)
    }
}
