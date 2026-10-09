//
//  PolicySet.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

/// The host policies of one environment plus an optional fallback for hosts nothing else matched.
public struct PolicySet: Hashable, Codable, Sendable {

    /// The host policies, consulted from the most specific match to the least.
    public let policies: [HostPolicy]

    /// The policy used when no host policy matches; unknown hosts are rejected when this is `nil`.
    public let defaultPolicy: PinningPolicy?

    public init(policies: [HostPolicy],
                defaultPolicy: PinningPolicy? = nil) {
        self.policies = policies
        self.defaultPolicy = defaultPolicy
    }
}
