//
//  PinGuardError.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

/// The errors PinGuard throws while hashing keys or applying remote configuration.
public enum PinGuardError: Error, Equatable, Sendable {

    /// Encountered a key type that isn't supported for pinning.
    case unsupportedKeyType

    /// The remote configuration signature did not verify against the payload.
    case invalidRemoteConfigSignature

    /// The remote configuration payload could not be decoded.
    case invalidRemoteConfigPayload

    /// The remote configuration payload declares a version this SDK does not understand.
    case unsupportedRemoteConfigVersion(Int)
}
