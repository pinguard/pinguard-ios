//
//  CertificateSummaryReader.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Foundation
import Security

enum CertificateSummaryReader {

    /// Returns the certificate's subject summary redacted to a wildcard of its registrable suffix.
    ///
    /// - Parameter certificate: The certificate whose subject will be read.
    /// - Returns: A value like `*.example.com`, or `nil` when the subject is not domain-like.
    static func redactedSubjectName(of certificate: SecCertificate) -> String? {
        guard let summary = SecCertificateCopySubjectSummary(certificate) else {
            return nil
        }

        return redactDomain(summary as String)
    }

    /// Returns the number of Subject Alternative Name entries present in the certificate.
    ///
    /// - Parameter certificate: The certificate to inspect.
    /// - Returns: The SAN entry count, or zero when the extension is absent or unreadable.
    static func subjectAlternativeNameCount(of certificate: SecCertificate) -> Int {
        let der = SecCertificateCopyData(certificate) as Data
        return SubjectAlternativeNameCounter.count(in: der)
    }

    /// Redacts a domain-like string to a wildcard form of its registrable suffix.
    ///
    /// - Parameter value: The input string to redact.
    /// - Returns: The redacted value, or `nil` when it has fewer than two labels.
    private static func redactDomain(_ value: String) -> String? {
        let labels = value.lowercased().split(separator: ".")
        guard labels.count >= 2 else {
            return nil
        }

        return "*." + labels.suffix(2).joined(separator: ".")
    }
}
