//
//  PinScope.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

public enum PinScope: String, Codable, Sendable {

    /// Applies to the leaf (end-entity) certificate.
    case leaf

    /// Applies to intermediate CA certificates.
    case intermediate

    /// Applies to the root CA certificate.
    case root

    /// Applies to any certificate in the chain.
    case any
}
