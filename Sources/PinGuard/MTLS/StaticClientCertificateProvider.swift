//
//  StaticClientCertificateProvider.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

public struct StaticClientCertificateProvider: ClientCertificateProvider {

    private let source: ClientCertificateSource

    public init(source: ClientCertificateSource) {
        self.source = source
    }

    /// Provides a client identity for the given host using the configured source.
    ///
    /// - Parameter host: The hostname requesting a client identity.
    /// - Returns: The identity loaded from the configured source.
    public func clientIdentity(for host: String) async -> ClientIdentityResult {
        ClientCertificateLoader.loadIdentity(from: source)
    }
}
