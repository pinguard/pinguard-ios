import Foundation

/// Events emitted during trust evaluation.
/// These events provide insight into the decision-making process.
public enum PinGuardEvent: Equatable, Sendable {

    case policyMissing(host: String)
    case systemTrustEvaluated(host: String, isTrusted: Bool)
    case systemTrustFailed(host: String, error: String?)
    case systemTrustFailedPermissive(host: String)
    case chainSummary(host: String, summary: ChainSummary)
    case pinMatched(host: String, pins: [Pin])
    case pinMismatch(host: String)
    case pinMismatchAllowedByFallback(host: String)
    case pinMismatchPermissive(host: String)
    case pinSetEmpty(host: String)
    case mtlsIdentityUsed(host: String)
    case mtlsIdentityMissing(host: String)
}
