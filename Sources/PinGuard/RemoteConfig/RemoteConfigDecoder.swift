//
//  RemoteConfigDecoder.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Foundation

public struct RemoteConfigDecoder: Sendable {

    private let verifier: any RemoteConfigVerifier

    public init(verifier: any RemoteConfigVerifier) {
        self.verifier = verifier
    }

    /// Verifies the blob's signature and decodes the policy set it carries.
    ///
    /// - Parameter blob: The signed configuration blob received from the backend.
    /// - Returns: The decoded policy set.
    public func decode(_ blob: RemoteConfigBlob) throws -> PolicySet {
        guard verifier.verify(blob: blob) else {
            throw PinGuardError.invalidRemoteConfigSignature
        }

        let payload: RemoteConfigPayload
        do {
            payload = try JSONDecoder().decode(RemoteConfigPayload.self, from: blob.payload)
        } catch {
            throw PinGuardError.invalidRemoteConfigPayload
        }

        guard payload.version == RemoteConfigPayload.currentVersion else {
            throw PinGuardError.unsupportedRemoteConfigVersion(payload.version)
        }

        return payload.policySet
    }
}
