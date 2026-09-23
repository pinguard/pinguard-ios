//
//  TrustDecisionReason.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

public enum TrustDecisionReason: Equatable, Sendable {

    /// One or more pins matched the server's certificate or public key.
    case pinMatch

    /// System trust failed but policy allows permissive acceptance.
    case systemTrustFailedPermissive

    /// Pins didn't match, but a defined fallback permitted trust.
    case pinMismatchAllowedByFallback

    /// Pins didn't match and were accepted due to permissive mode.
    case pinMismatchPermissive

    /// Trust evaluation failed and connection is not trusted.
    case trustFailed

    /// No applicable policy was found for this host or request.
    case policyMissing

    /// Pinning process failed due to configuration or evaluation error.
    case pinningFailed
}
