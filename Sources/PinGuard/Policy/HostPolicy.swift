//
//  HostPolicy.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

/// Binds a pinning policy to the hosts that match a pattern.
public struct HostPolicy: Hashable, Codable, Sendable {

    /// The pattern a host must match for this policy to apply.
    public let pattern: HostPattern

    /// The pinning policy applied to matching hosts.
    public let policy: PinningPolicy

    public init(pattern: HostPattern,
                policy: PinningPolicy) {
        self.pattern = pattern
        self.policy = policy
    }
}
