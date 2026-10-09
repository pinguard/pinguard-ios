//
//  RemoteConfigBlob.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation

/// A signed remote configuration as received from the backend.
public struct RemoteConfigBlob: Codable, Equatable, Sendable {

    /// The JSON payload, byte for byte as it was signed.
    public let payload: Data

    /// The signature computed over the payload.
    public let signature: Data

    /// The scheme used to sign the payload and the identifier of the key or secret.
    public let signatureType: RemoteConfigSignature

    public init(payload: Data,
                signature: Data,
                signatureType: RemoteConfigSignature) {
        self.payload = payload
        self.signature = signature
        self.signatureType = signatureType
    }
}
