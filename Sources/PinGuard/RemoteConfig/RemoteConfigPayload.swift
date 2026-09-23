//
//  RemoteConfigPayload.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

public struct RemoteConfigPayload: Codable, Equatable, Sendable {

    public static let currentVersion = 1

    public let version: Int
    public let policySet: PolicySet

    public init(version: Int = RemoteConfigPayload.currentVersion,
                policySet: PolicySet) {
        self.version = version
        self.policySet = policySet
    }
}
