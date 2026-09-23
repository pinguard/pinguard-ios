//
//  RemoteConfigSignature.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

public enum RemoteConfigSignature: Codable, Equatable, Sendable {

    /// HMAC-SHA256 signature verified with a shared secret.
    case hmacSHA256(secretID: String)

    /// ECDSA P-256 signature verified with a public key.
    case publicKey(keyID: String)
}
