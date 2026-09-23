//
//  ClientCertificateProvider.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

public protocol ClientCertificateProvider: Sendable {

    /// Provides a client identity to use for mTLS with the specified host.
    ///
    /// - Parameter host: The hostname requesting a client identity.
    /// - Returns: The identity lookup result for that host.
    func clientIdentity(for host: String) async -> ClientIdentityResult
}
