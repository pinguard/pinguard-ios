//
//  ClientCertificateLoaderTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Foundation
@testable import PinGuard
import Testing

@Suite
struct ClientCertificateLoaderTests {

    @Test
    func garbagePKCS12IsUnavailable() {
        let result = ClientCertificateLoader.loadIdentity(from: .pkcs12(data: Data("junk".utf8), password: "pw"))
        guard case .unavailable = result else {
            Issue.record("Expected .unavailable")
            return
        }
    }

    @Test
    func unknownKeychainTagIsUnavailable() async {
        let tag = Data("com.pinguard.tests.\(UUID().uuidString)".utf8)
        let provider = StaticClientCertificateProvider(source: .keychain(identityTag: tag))
        guard case .unavailable = await provider.clientIdentity(for: "api.example.com") else {
            Issue.record("Expected .unavailable")
            return
        }
    }
}
