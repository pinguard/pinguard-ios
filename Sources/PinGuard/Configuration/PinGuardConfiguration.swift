//
//  PinGuardConfiguration.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 16.02.2026.
//

/// The complete state of a `PinGuard` instance: its environments, the active one and the event sinks.
public struct PinGuardConfiguration: Sendable {

    /// Every registered environment keyed by its identifier.
    public var environments: [PinGuardEnvironment: PinGuardEnvironmentConfiguration]

    /// The environment whose policy set and mTLS settings are used for new challenges.
    public var current: PinGuardEnvironment

    /// The sinks that receive every event PinGuard emits.
    public var eventSinks: [any PinGuardEventSink]

    public init(environments: [PinGuardEnvironment: PinGuardEnvironmentConfiguration] = [:],
                current: PinGuardEnvironment = .prod,
                eventSinks: [any PinGuardEventSink] = [OSLogEventSink()]) {
        self.environments = environments
        self.current = current
        self.eventSinks = eventSinks
    }

    /// The policy set of the current environment, or an empty set when that environment is not registered.
    public var activePolicySet: PolicySet {
        environments[current]?.policySet ?? PolicySet(policies: [])
    }

    /// The mTLS configuration of the current environment, if it has one.
    public var activeMTLS: MTLSConfiguration? {
        environments[current]?.mtlsConfiguration
    }
}
