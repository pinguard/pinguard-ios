//
//  Errors.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation

/// Error cases of ssl pinning response or mTLS actions.
public enum PinGuardError: Error, Equatable {

    case invalidHost
    case policyNotFound
    case trustEvaluationFailed
    case trustNotTrusted
    case pinningFailed
    case unsupportedKeyType
    case invalidPin
    case invalidCertificate
    case mtlsIdentityUnavailable
}

/// Trust response struct for announcing certificate is trusted.
public struct TrustDecision: Equatable, Sendable {

    public enum Reason: Equatable, Sendable {
        case pinMatch
        case systemTrustAllowed
        case systemTrustFailedPermissive
        case pinMismatchAllowedByFallback
        case pinMismatchPermissive
        case trustFailed
        case policyMissing
        case pinningFailed
    }

    public let isTrusted: Bool
    public let reason: Reason
    public let events: [PinGuardEvent]
}
