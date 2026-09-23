//
//  PinGuardBuilder.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 16.02.2026.
//

public struct PinGuardBuilder: Sendable {

    private var environments: [PinGuardEnvironment: PinGuardEnvironmentConfiguration] = [:]
    private var current: PinGuardEnvironment = .prod
    private var customSinks: [any PinGuardEventSink] = []
    private var isSystemLoggingEnabled = true

    public init() {}

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

    /// Registers an additional sink that receives every emitted event.
    ///
    /// - Parameter sink: The sink to add.
    public mutating func addEventSink(_ sink: any PinGuardEventSink) {
        customSinks.append(sink)
    }

    /// Registers a closure that receives every emitted event.
    ///
    /// - Parameter handler: A closure invoked for each event.
    public mutating func telemetry(_ handler: @escaping @Sendable (PinGuardEvent) -> Void) {
        customSinks.append(ClosureEventSink(handler))
    }

    /// Enables or disables the built-in unified logging sink.
    ///
    /// - Parameter isEnabled: Pass `false` to stop PinGuard from writing to OSLog.
    public mutating func systemLogging(_ isEnabled: Bool) {
        isSystemLoggingEnabled = isEnabled
    }

    /// Produces the final configuration from the collected values.
    ///
    /// - Returns: A configuration ready to be applied to a `PinGuard` instance.
    public func build() -> PinGuardConfiguration {
        var sinks: [any PinGuardEventSink] = []
        if isSystemLoggingEnabled {
            sinks.append(OSLogEventSink())
        }
        sinks.append(contentsOf: customSinks)
        return PinGuardConfiguration(environments: environments,
                                     current: current,
                                     eventSinks: sinks)
    }
}
