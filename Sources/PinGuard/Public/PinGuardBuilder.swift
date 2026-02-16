//
//  PinGuardBuilder.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 16.02.2026.

/// `PinGuardBuilder` is a configuration builder used to assemble a `PinGuard` setup
/// for different deployment environments. It lets you:
/// - Register per-environment pinning policies and optional mTLS configuration via `environment(_:policySet:mtls:)`.
/// - Select which environment should be active using `selectEnvironment(_:)`.
/// - Provide an optional telemetry handler to observe `PinGuardEvent` emissions with `telemetry(_:)`.
///
/// Use this builder to prepare environment-specific security settings before initializing
/// components that rely on certificate pinning and (optionally) mutual TLS.
public struct PinGuardBuilder {

    private(set) var environments: [PinGuardEnvironment:
                                        PinGuardEnvironmentConfiguration] = [:]
    private(set) var current: PinGuardEnvironment = .prod
    private(set) var telemetry: (@Sendable (PinGuardEvent) -> Void)?

    /// Adds an environment configuration to the builder.
    ///
    /// - Parameters:
    ///   - env: The environment identifier to configure.
    ///   - policySet: The pinning policy set to use for this environment.
    ///   - mtls: Optional mTLS configuration for this environment.
    public mutating func environment(_ env: PinGuardEnvironment,
                                     policySet: PolicySet,
                                     mtls: MTLSConfiguration? = nil) {
        environments[env] = PinGuardEnvironmentConfiguration(policySet: policySet, mtlsConfiguration: mtls)
    }

    /// Selects the active environment for the resulting configuration.
    ///
    /// - Parameter env: The environment to set as current.
    public mutating func selectEnvironment(_ env: PinGuardEnvironment) {
        current = env
    }

    /// Sets a telemetry callback to receive emitted PinGuard events.
    ///
    /// - Parameter handler: A closure invoked for each event.
    public mutating func telemetry(_ handler: @Sendable @escaping (PinGuardEvent) -> Void) {
        telemetry = handler
    }
}
