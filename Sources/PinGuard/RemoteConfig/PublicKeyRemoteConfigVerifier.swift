//
//  PublicKeyRemoteConfigVerifier.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import CryptoKit
import Foundation

public struct PublicKeyRemoteConfigVerifier: RemoteConfigVerifier {

    private let publicKeyProvider: @Sendable (String) -> Data?

    public init(publicKeyProvider: @escaping @Sendable (String) -> Data?) {
        self.publicKeyProvider = publicKeyProvider
    }

    /// Verifies the ECDSA signature of the blob using the X9.63 public key resolved for its key identifier.
    ///
    /// - Parameter blob: The signed configuration blob to verify.
    /// - Returns: `true` when the signature is valid in either raw or DER form.
    public func verify(blob: RemoteConfigBlob) -> Bool {
        guard case .publicKey(let keyID) = blob.signatureType else {
            return false
        }

        guard let keyData = publicKeyProvider(keyID),
              let publicKey = try? P256.Signing.PublicKey(x963Representation: keyData),
              let signature = parseSignature(blob.signature) else {
            return false
        }

        return publicKey.isValidSignature(signature, for: blob.payload)
    }

    /// Parses a signature that may be encoded as raw r||s bytes or as DER.
    ///
    /// - Parameter data: The signature bytes to parse.
    /// - Returns: The parsed signature, or `nil` when neither encoding applies.
    private func parseSignature(_ data: Data) -> P256.Signing.ECDSASignature? {
        if let raw = try? P256.Signing.ECDSASignature(rawRepresentation: data) {
            return raw
        }
        return try? P256.Signing.ECDSASignature(derRepresentation: data)
    }
}
