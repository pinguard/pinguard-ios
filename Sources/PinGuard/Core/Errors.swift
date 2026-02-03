import Foundation

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

    public init(isTrusted: Bool, reason: Reason, events: [PinGuardEvent]) {
        self.isTrusted = isTrusted
        self.reason = reason
        self.events = events
    }
}

