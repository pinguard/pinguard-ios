//
//  HostPolicy.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

public struct HostPolicy: Hashable, Codable, Sendable {

    public let pattern: HostPattern
    public let policy: PinningPolicy

    public init(pattern: HostPattern,
                policy: PinningPolicy) {
        self.pattern = pattern
        self.policy = policy
    }
}
