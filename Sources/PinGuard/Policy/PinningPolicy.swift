//
//  PinningPolicy.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

private enum PinningPolicyCodingKey: String, CodingKey {

    case pins
    case failStrategy
    case requireSystemTrust
    case allowSystemTrustFallback
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

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: PinningPolicyCodingKey.self)
        self.pins = try container.decode([Pin].self, forKey: .pins)
        self.failStrategy = try container.decodeIfPresent(FailStrategy.self, forKey: .failStrategy) ?? .strict
        self.requireSystemTrust = try container.decodeIfPresent(Bool.self, forKey: .requireSystemTrust) ?? true
        self.allowSystemTrustFallback = try container.decodeIfPresent(Bool.self,
                                                                      forKey: .allowSystemTrustFallback) ?? false
    }

    /// Encodes every field of the policy.
    ///
    /// - Parameter encoder: The encoder to write the fields into.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: PinningPolicyCodingKey.self)
        try container.encode(pins, forKey: .pins)
        try container.encode(failStrategy, forKey: .failStrategy)
        try container.encode(requireSystemTrust, forKey: .requireSystemTrust)
        try container.encode(allowSystemTrustFallback, forKey: .allowSystemTrustFallback)
    }
}
