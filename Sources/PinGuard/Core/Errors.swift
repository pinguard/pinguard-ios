//
//  Errors.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation

/// Error cases of ssl pinning response or mTLS actions.
public enum PinGuardError: Error, Equatable {

    /// The provided host is invalid or doesn't match the expected format.
    case invalidHost

    /// No pinning or mTLS policy found for the given host.
    case policyNotFound

    /// System trust evaluation couldn't be completed successfully.
    case trustEvaluationFailed

    /// The server's certificate chain is not trusted by the system.
    case trustNotTrusted

    /// SSL pinning validation failed.
    case pinningFailed

    /// Encountered a key type that isn't supported for pinning.
    case unsupportedKeyType

    /// The configured pin value is malformed or unusable.
    case invalidPin

    /// The certificate data is invalid or couldn't be parsed.
    case invalidCertificate

    /// A required client identity/certificate for mTLS is unavailable.
    case mtlsIdentityUnavailable
}

/// Trust response struct for announcing certificate is trusted.
public struct TrustDecision: Equatable, Sendable {

    public enum Reason: Equatable, Sendable {

        /// One or more pins matched the server's certificate or public key.
        case pinMatch

        /// Trusted based on successful system trust evaluation.
        case systemTrustAllowed

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

    public let isTrusted: Bool
    public let reason: Reason
    public let events: [PinGuardEvent]
}
