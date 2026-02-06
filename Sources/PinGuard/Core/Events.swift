//
//  Events.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation

/// Events emitted during trust evaluation.
public enum PinGuardEvent: Equatable, Sendable {

    /// No policy could be found for the given host.
    ///
    /// - Parameter host: The hostname for which policy lookup failed.
    case policyMissing(host: String)

    /// Result of system trust evaluation for the given host.
    ///
    /// - Parameters:
    ///   - host: The hostname whose certificate chain was evaluated.
    ///   - isTrusted: Whether the system trust evaluation considered the chain trusted.
    case systemTrustEvaluated(host: String, isTrusted: Bool)

    /// System trust evaluation failed with an optional error message.
    ///
    /// - Parameters:
    ///   - host: The hostname whose evaluation failed.
    ///   - error: A human-readable error description if available.
    case systemTrustFailed(host: String, error: String?)

    /// System trust failed but permissive mode allowed continuation.
    ///
    /// - Parameter host: The hostname for which permissive behavior applied.
    case systemTrustFailedPermissive(host: String)

    /// Provides a summary of the evaluated certificate chain.
    ///
    /// - Parameters:
    ///   - host: The hostname whose chain was summarized.
    ///   - summary: Details describing the server's certificate chain.
    case chainSummary(host: String, summary: ChainSummary)

    /// One or more pins matched the server's certificate or key material.
    ///
    /// - Parameters:
    ///   - host: The hostname whose pins matched.
    ///   - pins: The set of pins that produced a match.
    case pinMatched(host: String, pins: [Pin])

    /// Pinning failed because no configured pins matched.
    ///
    /// - Parameter host: The hostname for which pinning failed.
    case pinMismatch(host: String)

    /// Pin mismatch occurred but a configured fallback allowed the connection.
    ///
    /// - Parameter host: The hostname for which fallback permitted trust.
    case pinMismatchAllowedByFallback(host: String)

    /// Pin mismatch occurred and was accepted due to permissive mode.
    ///
    /// - Parameter host: The hostname accepted despite pin mismatch.
    case pinMismatchPermissive(host: String)

    /// Pinning couldn't proceed because the configured pin set is empty.
    ///
    /// - Parameter host: The hostname with an empty pin set.
    case pinSetEmpty(host: String)

    /// mTLS client identity was successfully used.
    ///
    /// - Parameter host: The hostname for which the identity was applied.
    case mtlsIdentityUsed(host: String)

    /// mTLS client identity was required but not available.
    ///
    /// - Parameter host: The hostname that required a client identity.
    case mtlsIdentityMissing(host: String)
}

