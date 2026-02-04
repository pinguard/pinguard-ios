import Foundation

public enum FailStrategy: String, Codable, Sendable {

    case strict
    case permissive
}

public enum PinType: String, Codable, Sendable {

    case spki
    case certificate
    case ca
}

public enum PinRole: String, Codable, Sendable {

    case primary
    case backup
}

public enum PinScope: String, Codable, Sendable {

    case leaf
    case intermediate
    case root
    case any
}

public struct Pin: Hashable, Codable, Sendable {

    public let type: PinType
    public let hash: String
    public let role: PinRole
    public let scope: PinScope

    public init(type: PinType,
                hash: String,
                role: PinRole = .primary,
                scope: PinScope = .any) {
        self.type = type
        self.hash = hash
        self.role = role
        self.scope = scope
    }
}

public struct PinningPolicy: Hashable, Codable {

    public let pins: [Pin]
    public let failStrategy: FailStrategy
    public let requireSystemTrust: Bool
    public let allowSystemTrustFallback: Bool

    public init(pins: [Pin],
                failStrategy: FailStrategy = .strict,
                requireSystemTrust: Bool = true,
                allowSystemTrustFallback: Bool = false) {
        self.pins = pins
        self.failStrategy = failStrategy
        self.requireSystemTrust = requireSystemTrust
        self.allowSystemTrustFallback = allowSystemTrustFallback
    }
}

public enum HostPattern: Hashable, Codable {

    case exact(String)
    case wildcard(String)

    public var rawValue: String {
        switch self {
        case .exact(let value):
            return value
        case .wildcard(let value):
            return "*." + value
        }
    }

    public static func parse(_ pattern: String) -> HostPattern {
        let normalized = HostPattern.normalizeHost(pattern)
        if normalized.hasPrefix("*.") {
            return .wildcard(String(normalized.dropFirst(2)))
        }
        return .exact(normalized)
    }

    static func normalizeHost(_ host: String) -> String {
        host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
    }
}

public struct HostPolicy: Hashable, Codable {

    public let pattern: HostPattern
    public let policy: PinningPolicy

    public init(pattern: HostPattern,
                policy: PinningPolicy) {
        self.pattern = pattern
        self.policy = policy
    }
}

public struct PolicySet: Hashable, Codable {

    public let policies: [HostPolicy]
    public let defaultPolicy: PinningPolicy?

    public init(policies: [HostPolicy],
                defaultPolicy: PinningPolicy? = nil) {
        self.policies = policies
        self.defaultPolicy = defaultPolicy
    }
}
