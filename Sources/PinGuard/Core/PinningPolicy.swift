//
//  PinningPolicy.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation

public enum FailStrategy: String, Codable, Sendable {

    /// Fail immediately when trust or pinning checks fail.
    case strict

    /// Allow the connection to proceed despite failures under a permissive policy.
    case permissive
}

public enum PinType: String, Codable, Sendable {

    /// Pin is a hash of the certificate's Subject Public Key Info (SPKI).
    case spki

    /// Pin is a hash of the full certificate DER data.
    case certificate

    /// Pin targets a CA certificate (intermediate or root) in the chain.
    case ca
}

public enum PinRole: String, Codable, Sendable {

    /// Primary pin used for normal validation.
    case primary

    /// Backup pin used for key rotation or as a fallback.
    case backup
}

public enum PinScope: String, Codable, Sendable {

    /// Applies to the leaf (end-entity) certificate.
    case leaf

    /// Applies to intermediate CA certificates.
    case intermediate

    /// Applies to the root CA certificate.
    case root

    /// Applies to any certificate in the chain.
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

public struct PinningPolicy: Hashable, Codable, Sendable {

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

public enum HostPattern: Hashable, Codable, Sendable {

    /// Matches only the exact hostname value.
    ///
    /// - Parameter value: The exact hostname to match.
    case exact(String)

    /// Matches any single-label subdomain of the given suffix (e.g., *.example.com).
    ///
    /// - Parameter value: The suffix domain to match (without the "*." prefix).
    case wildcard(String)

    public var rawValue: String {
        switch self {
        case .exact(let value):
            return value
        case .wildcard(let value):
            return "*." + value
        }
    }

    /// Parses a host pattern string into a HostPattern, interpreting "*." as a wildcard.
    ///
    /// - Parameter pattern: The host pattern string to parse.
    public static func parse(_ pattern: String) -> HostPattern {
        let normalized = HostPattern.normalizeHost(pattern)
        if normalized.hasPrefix("*.") {
            return .wildcard(String(normalized.dropFirst(2)))
        }
        return .exact(normalized)
    }

    /// Normalizes a host for matching by lowercasing and trimming leading/trailing dots.
    ///
    /// - Parameter host: The host string to normalize.
    static func normalizeHost(_ host: String) -> String {
        host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
    }
}

public struct HostPolicy: Hashable, Codable, Sendable {

    public let pattern: HostPattern
    public let policy: PinningPolicy

    public init(pattern: HostPattern,
                policy: PinningPolicy) {
        self.pattern = pattern
        self.policy = policy
    }
}

public struct PolicySet: Hashable, Codable, Sendable {

    public let policies: [HostPolicy]
    public let defaultPolicy: PinningPolicy?

    public init(policies: [HostPolicy],
                defaultPolicy: PinningPolicy? = nil) {
        self.policies = policies
        self.defaultPolicy = defaultPolicy
    }
}
