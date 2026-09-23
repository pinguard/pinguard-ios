//
//  SecTrustSystemEvaluator.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Foundation
import Security

struct SecTrustSystemEvaluator: SystemTrustEvaluating {

    private static let queue = DispatchQueue(label: "com.pinguard.system-trust", qos: .userInitiated)

    /// Applies the SSL policy for the host and lets the system evaluate the chain off the calling executor.
    ///
    /// - Parameters:
    ///   - trust: The trust object representing the server's certificate chain.
    ///   - host: The normalized hostname the certificate must be valid for.
    /// - Returns: Whether the system trusts the chain and an optional error description.
    func evaluate(_ trust: SecTrust, host: String) async -> SystemTrustResult {
        SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString))
        return await withCheckedContinuation { continuation in
            Self.queue.sync {
                let status = SecTrustEvaluateAsyncWithError(trust, Self.queue) { _, isTrusted, error in
                    continuation.resume(returning: SystemTrustResult(isTrusted: isTrusted,
                                                                     errorDescription: error?.localizedDescription))
                }
                guard status == errSecSuccess else {
                    let message = SecCopyErrorMessageString(status, nil) as String?
                    continuation.resume(returning: SystemTrustResult(isTrusted: false, errorDescription: message))
                    return
                }
            }
        }
    }
}
