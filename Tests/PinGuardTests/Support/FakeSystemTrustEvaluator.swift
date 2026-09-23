//
//  FakeSystemTrustEvaluator.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

@testable import PinGuard
import Security

struct FakeSystemTrustEvaluator: SystemTrustEvaluating {

    let isTrusted: Bool
    let errorDescription: String?

    init(isTrusted: Bool,
         errorDescription: String? = nil) {
        self.isTrusted = isTrusted
        self.errorDescription = errorDescription
    }

    /// Returns the configured result regardless of the trust object.
    ///
    /// - Parameters:
    ///   - trust: Ignored.
    ///   - host: Ignored.
    /// - Returns: The fixed result.
    func evaluate(_ trust: SecTrust, host: String) async -> SystemTrustResult {
        SystemTrustResult(isTrusted: isTrusted, errorDescription: errorDescription)
    }
}
