//
//  PolicySet.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

public struct PolicySet: Hashable, Codable, Sendable {

    public let policies: [HostPolicy]
    public let defaultPolicy: PinningPolicy?

    public init(policies: [HostPolicy],
                defaultPolicy: PinningPolicy? = nil) {
        self.policies = policies
        self.defaultPolicy = defaultPolicy
    }
}
