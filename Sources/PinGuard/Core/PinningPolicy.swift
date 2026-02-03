import Foundation

enum FailStrategy: String, Codable, Sendable {

    case strict
    case permissive
}

enum PinType: String, Codable, Sendable {

    case spki
    case certificate
    case ca
}

enum PinRole: String, Codable, Sendable {

    case primary
    case backup
}

enum PinScope: String, Codable, Sendable {

    case leaf
    case intermediate
    case root
    case any
}

struct Pin: Hashable, Codable, Sendable {

    let type: PinType
    let hash: String
    let role: PinRole
    let scope: PinScope

    init(type: PinType, hash: String, role: PinRole = .primary, scope: PinScope = .any) {
        self.type = type
        self.hash = hash
        self.role = role
        self.scope = scope
    }
}

struct PinningPolicy: Hashable, Codable {

    let pins: [Pin]
    let failStrategy: FailStrategy
    let requireSystemTrust: Bool
    let allowSystemTrustFallback: Bool

    init(pins: [Pin],
         failStrategy: FailStrategy = .strict,
         requireSystemTrust: Bool = true,
         allowSystemTrustFallback: Bool = false) {
        self.pins = pins
        self.failStrategy = failStrategy
        self.requireSystemTrust = requireSystemTrust
        self.allowSystemTrustFallback = allowSystemTrustFallback
    }
}

enum HostPattern: Hashable, Codable {

    case exact(String)
    case wildcard(String)

    var rawValue: String {
        switch self {
        case .exact(let value):
            return value
        case .wildcard(let value):
            return "*." + value
        }
    }

    static func parse(_ pattern: String) -> HostPattern {
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

struct HostPolicy: Hashable, Codable {

    let pattern: HostPattern
    let policy: PinningPolicy
}

public struct PolicySet: Hashable, Codable {

    let policies: [HostPolicy]
    let defaultPolicy: PinningPolicy?

    init(policies: [HostPolicy], defaultPolicy: PinningPolicy? = nil) {
        self.policies = policies
        self.defaultPolicy = defaultPolicy
    }
}
