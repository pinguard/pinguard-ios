//
//  CertificateCandidate.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 10.02.2026.
//

import Security

struct CertificateCandidate {

    let certificate: SecCertificate
    let spkiHash: String
    let certificateHash: String
    let scope: CertificateScope

    init(certificate: SecCertificate,
         scope: CertificateScope) {
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
