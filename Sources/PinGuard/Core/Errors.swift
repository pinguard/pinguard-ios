import Foundation

enum PinGuardError: Error, Equatable {

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

struct TrustDecision: Equatable, Sendable {

    enum Reason: Equatable, Sendable {
        case pinMatch
        case systemTrustAllowed
        case systemTrustFailedPermissive
        case pinMismatchAllowedByFallback
        case pinMismatchPermissive
        case trustFailed
        case policyMissing
        case pinningFailed
    }

    let isTrusted: Bool
    let reason: Reason
    let events: [PinGuardEvent]
}
