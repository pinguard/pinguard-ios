//
//  PinType.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

public enum PinType: String, Codable, Sendable {

    /// Pin is a hash of the certificate's Subject Public Key Info (SPKI).
    case spki

    /// Pin is a hash of the full certificate DER data.
    case certificate

    /// Pin targets a CA certificate (intermediate or root) in the chain.
    case ca
}
