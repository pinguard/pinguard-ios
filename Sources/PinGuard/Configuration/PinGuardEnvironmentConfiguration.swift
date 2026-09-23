//
//  PinGuardEnvironmentConfiguration.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 16.02.2026.
//

public struct PinGuardEnvironmentConfiguration: Sendable {

    public let policySet: PolicySet
    public let mtlsConfiguration: MTLSConfiguration?

    public init(policySet: PolicySet,
                mtlsConfiguration: MTLSConfiguration? = nil) {
        self.policySet = policySet
        self.mtlsConfiguration = mtlsConfiguration
    }
}
