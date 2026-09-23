//
//  RemoteConfigBlob.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation

public struct RemoteConfigBlob: Codable, Equatable, Sendable {

    public let payload: Data
    public let signature: Data
    public let signatureType: RemoteConfigSignature

    public init(payload: Data,
                signature: Data,
                signatureType: RemoteConfigSignature) {
        self.payload = payload
        self.signature = signature
        self.signatureType = signatureType
    }
}
