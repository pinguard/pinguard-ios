//
//  RemoteConfigPayload.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

/// The JSON document carried inside a remote configuration blob.
public struct RemoteConfigPayload: Codable, Equatable, Sendable {

    /// The payload version this SDK understands.
    public static let currentVersion = 1

    /// The version declared by the payload; it must equal `currentVersion`.
    public let version: Int

    /// The policy set that replaces the one of the target environment.
    public let policySet: PolicySet

    public init(version: Int = RemoteConfigPayload.currentVersion,
                policySet: PolicySet) {
        self.version = version
        self.policySet = policySet
    }
}
