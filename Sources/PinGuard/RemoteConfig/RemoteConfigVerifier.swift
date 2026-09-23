//
//  RemoteConfigVerifier.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

public protocol RemoteConfigVerifier: Sendable {

    /// Verifies the signature of the provided remote configuration blob.
    ///
    /// - Parameter blob: The signed configuration blob to verify.
    /// - Returns: `true` when the signature is valid for the payload.
    func verify(blob: RemoteConfigBlob) -> Bool
}
