//
//  HMACRemoteConfigVerifier.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import CryptoKit
import Foundation

public struct HMACRemoteConfigVerifier: RemoteConfigVerifier {

    private let secretProvider: @Sendable (String) -> Data?

    public init(secretProvider: @escaping @Sendable (String) -> Data?) {
        self.secretProvider = secretProvider
    }

    /// Verifies the HMAC of the blob using the secret resolved for its secret identifier.
    ///
    /// - Parameter blob: The signed configuration blob to verify.
    /// - Returns: `true` when the HMAC matches, using a constant-time comparison.
    public func verify(blob: RemoteConfigBlob) -> Bool {
        guard case .hmacSHA256(let secretID) = blob.signatureType else {
            return false
        }

        guard let secret = secretProvider(secretID) else {
            return false
        }

        let key = SymmetricKey(data: secret)
        return HMAC<SHA256>.isValidAuthenticationCode(blob.signature, authenticating: blob.payload, using: key)
    }
}
