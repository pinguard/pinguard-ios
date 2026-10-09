//
//  PinGuardEnvironmentConfiguration.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 16.02.2026.
//

/// The pinning policies and optional mTLS settings that belong to one environment.
public struct PinGuardEnvironmentConfiguration: Sendable {

    /// The host policies used to evaluate server trust in this environment.
    public let policySet: PolicySet

    /// The client certificate settings used when a server asks for one, if any.
    public let mtlsConfiguration: MTLSConfiguration?

    public init(policySet: PolicySet,
                mtlsConfiguration: MTLSConfiguration? = nil) {
        self.policySet = policySet
        self.mtlsConfiguration = mtlsConfiguration
    }
}
