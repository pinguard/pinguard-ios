//
//  PinGuardConfiguration.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 16.02.2026.
//

/// `PinGuardConfiguration` represents the finalized configuration used by PinGuard
/// at runtime. It contains:
/// - A mapping of `PinGuardEnvironment` to their `PinGuardEnvironmentConfiguration`.
/// - The `current` environment that is considered active.
/// - An optional `telemetry` closure to receive `PinGuardEvent`s emitted by the system.
///
/// It also provides convenience accessors:
/// - `activePolicySet` to retrieve the pinning policies for the active environment.
/// - `activeMTLS` to retrieve the optional mTLS configuration for the active environment.
public struct PinGuardConfiguration: Sendable {

    public var environments: [PinGuardEnvironment: PinGuardEnvironmentConfiguration]
    public var current: PinGuardEnvironment
    public var telemetry: (@Sendable (PinGuardEvent) -> Void)?

    /// Initializes a `PinGuardConfiguration` with environment-specific settings and an optional
    /// telemetry handler.
    ///
    /// - Parameters:
    ///   - environments: A dictionary mapping each `PinGuardEnvironment` to its `PinGuardEnvironmentConfiguration`.
    ///   - current: The environment to consider active for resolving policies and mTLS.
    ///   - telemetry: An optional closure that receives `PinGuardEvent`s emitted by the system.
    public init(environments: [PinGuardEnvironment: PinGuardEnvironmentConfiguration],
                current: PinGuardEnvironment,
                telemetry: (@Sendable (PinGuardEvent) -> Void)? = nil) {
        self.environments = environments
        self.current = current
        self.telemetry = telemetry
    }

    public var activePolicySet: PolicySet {
        environments[current]?.policySet ?? PolicySet(policies: [])
    }

    public var activeMTLS: MTLSConfiguration? {
        environments[current]?.mtlsConfiguration
    }
}
