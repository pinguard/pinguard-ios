//
//  PinGuardConfiguration.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 16.02.2026.
//

public struct PinGuardConfiguration: Sendable {

    public var environments: [PinGuardEnvironment: PinGuardEnvironmentConfiguration]
    public var current: PinGuardEnvironment
    public var eventSinks: [any PinGuardEventSink]

    public init(environments: [PinGuardEnvironment: PinGuardEnvironmentConfiguration] = [:],
                current: PinGuardEnvironment = .prod,
                eventSinks: [any PinGuardEventSink] = [OSLogEventSink()]) {
        self.environments = environments
        self.current = current
        self.eventSinks = eventSinks
    }

    public var activePolicySet: PolicySet {
        environments[current]?.policySet ?? PolicySet(policies: [])
    }

    public var activeMTLS: MTLSConfiguration? {
        environments[current]?.mtlsConfiguration
    }
}
