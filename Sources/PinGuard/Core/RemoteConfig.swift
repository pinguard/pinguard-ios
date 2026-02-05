//
//  RemoteConfig.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation

/// Signature scheme for remote configuration blobs.
public enum RemoteConfigSignature: Codable, Equatable, Sendable {

    case hmacSHA256(secretID: String)
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

    func verify(blob: RemoteConfigBlob) -> Bool
}

/// Threat model documentation for remote configuration.
public enum RemoteConfigThreatModel {

    public static let unsignedConfigWarning =
    "Unsigned remote configuration is insecure; it allows a network attacker to disable pinning."
}
