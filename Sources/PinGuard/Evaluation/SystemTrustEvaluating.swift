//
//  SystemTrustEvaluating.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Security

protocol SystemTrustEvaluating: Sendable {

    /// Evaluates the trust object against the SSL policy for the given host.
    ///
    /// - Parameters:
    ///   - trust: The trust object representing the server's certificate chain.
    ///   - host: The normalized hostname the certificate must be valid for.
    /// - Returns: Whether the system trusts the chain and an optional error description.
    func evaluate(_ trust: SecTrust, host: String) async -> SystemTrustResult
}
