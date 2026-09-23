//
//  PinGuardEvent.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

public enum PinGuardEvent: Equatable, Sendable {

    /// No policy could be found for the given host.
    case policyMissing(host: String)

    /// Result of system trust evaluation for the given host.
    case systemTrustEvaluated(host: String, isTrusted: Bool)

    /// System trust evaluation failed with an optional error message.
    case systemTrustFailed(host: String, error: String?)

    /// System trust failed but permissive mode allowed continuation.
    case systemTrustFailedPermissive(host: String)

    /// Provides a summary of the evaluated certificate chain.
    case chainSummary(host: String, summary: ChainSummary)

    /// One or more pins matched the server's certificate or key material.
    case pinMatched(host: String, pins: [Pin])

    /// Pinning failed because no configured pins matched.
    case pinMismatch(host: String)

    /// Pin mismatch occurred but a configured fallback allowed the connection.
    case pinMismatchAllowedByFallback(host: String)

    /// Pin mismatch occurred and was accepted due to permissive mode.
    case pinMismatchPermissive(host: String)

    /// Pinning couldn't proceed because the configured pin set is empty.
    case pinSetEmpty(host: String)

    /// mTLS client identity was successfully used.
    case mtlsIdentityUsed(host: String)

    /// mTLS client identity was required but not available.
    case mtlsIdentityMissing(host: String)

    /// A verified remote configuration replaced the policy set of an environment.
    case remoteConfigApplied(environment: String)

    /// A remote configuration was rejected before it could change anything.
    case remoteConfigRejected(environment: String, error: String)
}
