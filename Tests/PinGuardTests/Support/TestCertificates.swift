//
//  TestCertificates.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Foundation
import Security

enum TestCertificates {

    static let leafSPKIHash = "8gG0We88T4x3TWO4hw/aNf0KQbc3yETE9W+C010Lh3U="
    static let rootSPKIHash = "qCTwira8KanSA4XAXJUQNDG1en54SiJxVl6HCPkBESE="
    static let leafCertificateHash = "0C6TZq6CigCbA53+tPG14yvNz9tY7ndiJbDblJIEvtM="
    static let rootCertificateHash = "S6xa8qj1w3H1MLf1Tb7A23CaTCTHJvWk1OopbZPLb+s="
    static let leafSANCount = 3

    static let leafDER = Data(base64Encoded: """
        MIIBmjCCAUCgAwIBAgIJAM1P/TGs6tKDMAoGCCqGSM49BAMCMCAxHjAcBgNVBAMMFVBpbkd1YXJkIFRlc3QgUm9vdCBDQTAeFw0y\
        NjA5MjMxMDIxNDJaFw0zNjA5MjAxMDIxNDJaMBoxGDAWBgNVBAMMD2FwaS5leGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49\
        AwEHA0IABJjUzyP2uIIKQYp+jSYbYNOAmqiJNHYCPhqgnQvvQ8499jjlfJniV6b5aKdj0fzLRfFGliy9b+/ZHbbijSrBqV2jaTBn\
        MDgGA1UdEQQxMC+CD2FwaS5leGFtcGxlLmNvbYIPd3d3LmV4YW1wbGUuY29tggtleGFtcGxlLmNvbTAJBgNVHRMEAjAAMAsGA1Ud\
        DwQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAKBggqhkjOPQQDAgNIADBFAiB14DtFKNrFLgwbqSTxQwTm12Gaq7zcFyTlfDyG\
        1eI+6wIhANBrZx8XuLAPM2rxwwa/HmdiUTI5zoQ1azD7AG2itQiK
        """) ?? Data()

    static let rootDER = Data(base64Encoded: """
        MIIBWzCCAQCgAwIBAgIJAPsQ9RqhEQU9MAoGCCqGSM49BAMCMCAxHjAcBgNVBAMMFVBpbkd1YXJkIFRlc3QgUm9vdCBDQTAeFw0y\
        NjA5MjMxMDIxNDJaFw0zNjA5MjAxMDIxNDJaMCAxHjAcBgNVBAMMFVBpbkd1YXJkIFRlc3QgUm9vdCBDQTBZMBMGByqGSM49AgEG\
        CCqGSM49AwEHA0IABA40XfE+Nu1QbQy8eCahoM7ktDLEMPl2L2Gs+vfu2NoVZcMGUIb11YUMSrwPF6iX3+UfONu4Stuj1SwQURWW\
        hIKjIzAhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA0kAMEYCIQCSgNYud+KOuMHxMnH6009D\
        AhAxR9c66vEGWW8sk0crPwIhAOM6jemW1SKbxRXIApHQpyJ3HChuHFhYXidI6fUjYm9S
        """) ?? Data()

    static let intermediateCertificateHash = "JkIxd31JVLquMXtkQbU3zoIGvwFzwC+teggxQNFQT3A="
    static let intermediateSPKIHash = "x3+oRjhSqI9uOsjwxNuQlDiTa4wfajDSh12CbI2JZJA="

    static let intermediateDER = Data(base64Encoded: """
        MIIBZTCCAQugAwIBAgIJAM1P/TGs6tKEMAoGCCqGSM49BAMCMCAxHjAcBgNVBAMMFVBpbkd1YXJkIFRlc3QgUm9vdCBDQTAeFw0y\
        NjA5MjMxMDMxMTVaFw0zNjA5MjAxMDMxMTVaMCgxJjAkBgNVBAMMHVBpbkd1YXJkIFRlc3QgSW50ZXJtZWRpYXRlIENBMFkwEwYH\
        KoZIzj0CAQYIKoZIzj0DAQcDQgAEbThl2EkgYg6V+WFdT5ZrP1eqIa9a9KjCsLG+o6eHT870Hd2oObxFdEApJDh61Boc9U7VGBrF\
        dihisNvS0Yq9XaMmMCQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIhALrh/rKH\
        hVFjslw6sY4/W5DdkvqtzYoi7GWC0FCe1dPgAiARuqNe1bI3pGjroCzzVSxfHH0TE+J0SG7ExmuFk6AGsA==
        """) ?? Data()

    static let intermediateLeafDER = Data(base64Encoded: """
        MIIBhDCCASqgAwIBAgIJAI21B7UH7t9nMAoGCCqGSM49BAMCMCgxJjAkBgNVBAMMHVBpbkd1YXJkIFRlc3QgSW50ZXJtZWRpYXRl\
        IENBMB4XDTI2MDkyMzEwMzExNVoXDTM2MDkyMDEwMzExNVowGjEYMBYGA1UEAwwPY2RuLmV4YW1wbGUuY29tMFkwEwYHKoZIzj0C\
        AQYIKoZIzj0DAQcDQgAESvjNF5cmmiwjJnOGEZazSLhP7v+dD90lo3YFGyWtnXHCP1UNIaVoId9h+AOunEOS9nsz7wU5mfiALpbP\
        PTU/cKNLMEkwGgYDVR0RBBMwEYIPY2RuLmV4YW1wbGUuY29tMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgeAMBMGA1UdJQQMMAoGCCsG\
        AQUFBwMBMAoGCCqGSM49BAMCA0gAMEUCIQD26Lt3Y4VE80BEz6RrdVtxn9ap8ilfhw5Qqv5vQwtslgIgYO5Q4kqT3vM/BkUoXVqv\
        bA4ojNzQTXindcaZLla2OJg=
        """) ?? Data()

    static var intermediate: SecCertificate? {
        SecCertificateCreateWithData(nil, intermediateDER as CFData)
    }

    static var intermediateLeaf: SecCertificate? {
        SecCertificateCreateWithData(nil, intermediateLeafDER as CFData)
    }

    static var leaf: SecCertificate? {
        SecCertificateCreateWithData(nil, leafDER as CFData)
    }

    static var root: SecCertificate? {
        SecCertificateCreateWithData(nil, rootDER as CFData)
    }

    /// Builds a trust object for the given certificates and SSL host.
    ///
    /// - Parameters:
    ///   - certificates: The chain to evaluate, leaf first.
    ///   - host: The hostname used for the SSL policy.
    /// - Returns: The trust object, or `nil` when Security refuses to create it.
    static func makeTrust(certificates: [SecCertificate], host: String = "api.example.com") -> SecTrust? {
        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, host as CFString)
        let status = SecTrustCreateWithCertificates(certificates as CFArray, policy, &trust)
        guard status == errSecSuccess else {
            return nil
        }

        return trust
    }

    /// Builds a three-certificate trust object for cdn.example.com issued through the intermediate.
    ///
    /// - Returns: The trust object, or `nil` when a fixture cannot be decoded.
    static func makeThreeCertificateTrust() -> SecTrust? {
        guard let intermediateLeaf, let intermediate, let root else {
            return nil
        }

        return makeTrust(certificates: [intermediateLeaf, intermediate, root], host: "cdn.example.com")
    }

    /// Builds a leaf-plus-root trust object for api.example.com.
    ///
    /// - Returns: The trust object, or `nil` when a fixture cannot be decoded.
    static func makeChainTrust() -> SecTrust? {
        guard let leaf, let root else {
            return nil
        }

        return makeTrust(certificates: [leaf, root])
    }
}
