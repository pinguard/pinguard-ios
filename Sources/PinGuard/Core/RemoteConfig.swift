//
//  RemoteConfig.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation

/// Signature scheme for remote configuration blobs.
public enum RemoteConfigSignature: Codable, Equatable, Sendable {

    /// HMAC-SHA256 signature verified with a shared secret.
    ///
    /// - Parameter secretID: The identifier of the shared secret used to compute/verify the HMAC.
    case hmacSHA256(secretID: String)

    /// Asymmetric signature verified with a public key.
    ///
    /// - Parameter keyID: The identifier of the public key used to verify the signature.
    case publicKey(keyID: String)
}

/// A signed remote configuration payload.
public struct RemoteConfigBlob: Codable, Equatable, Sendable {

    public let payload: Data
    public let signature: Data
    public let signatureType: RemoteConfigSignature

    public init(payload: Data, signature: Data, signatureType: RemoteConfigSignature) {
        self.payload = payload
        self.signature = signature
        self.signatureType = signatureType
    }
}

/// Verifies the signature of a remote configuration blob.
public protocol RemoteConfigVerifier: Sendable {

    /// Verifies the signature of the provided remote configuration blob.
    ///
    /// - Parameter blob: The signed configuration blob to verify.
    func verify(blob: RemoteConfigBlob) -> Bool
}

/// Threat model documentation for remote configuration.
public enum RemoteConfigThreatModel {

    public static let unsignedConfigWarning =
    "Unsigned remote configuration is insecure; it allows a network attacker to disable pinning."
}
