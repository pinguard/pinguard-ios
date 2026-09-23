//
//  CertificateScopeTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

@testable import PinGuard
import Testing

@Suite
struct CertificateScopeTests {

    @Test(arguments: [CertificateScope.leaf, .intermediate, .root])
    func anyPinScopeCoversEveryCertificate(scope: CertificateScope) {
        #expect(scope.contains(.any))
    }

    @Test
    func specificPinScopesMatchOnlyTheirPosition() {
        #expect(CertificateScope.leaf.contains(.leaf))
        #expect(!CertificateScope.leaf.contains(.root))
        #expect(CertificateScope.intermediate.contains(.intermediate))
        #expect(!CertificateScope.intermediate.contains(.leaf))
        #expect(CertificateScope.root.contains(.root))
        #expect(!CertificateScope.root.contains(.intermediate))
    }

    @Test
    func onlyLeafIsNotCA() {
        #expect(!CertificateScope.leaf.isCA)
        #expect(CertificateScope.intermediate.isCA)
        #expect(CertificateScope.root.isCA)
    }
}
