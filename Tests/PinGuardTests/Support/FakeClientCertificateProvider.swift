//
//  FakeClientCertificateProvider.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

@testable import PinGuard

struct FakeClientCertificateProvider: ClientCertificateProvider {

    let result: FakeClientIdentityOutcome

    /// Returns the configured outcome.
    ///
    /// - Parameter host: Ignored.
    /// - Returns: The identity result mapped from the configured outcome.
    func clientIdentity(for host: String) async -> ClientIdentityResult {
        switch result {
        case .renewalRequired:
            return .renewalRequired
        case .unavailable:
            return .unavailable
        }
    }
}
