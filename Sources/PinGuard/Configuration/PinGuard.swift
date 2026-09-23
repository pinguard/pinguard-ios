//
//  PinGuard.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Security

public actor PinGuard {

    public static let shared = PinGuard()

    private var configuration: PinGuardConfiguration
    private let systemTrustEvaluator: any SystemTrustEvaluating

    public init(configuration: PinGuardConfiguration = PinGuardConfiguration()) {
        self.init(configuration: configuration, systemTrustEvaluator: SecTrustSystemEvaluator())
    }

    init(configuration: PinGuardConfiguration,
         systemTrustEvaluator: any SystemTrustEvaluating) {
        self.configuration = configuration
        self.systemTrustEvaluator = systemTrustEvaluator
    }

    public var currentConfiguration: PinGuardConfiguration {
        configuration
    }

    /// Configures the shared instance using a builder closure.
    ///
    /// - Parameter build: A closure that populates the builder with environments and settings.
    public static func configure(_ build: (inout PinGuardBuilder) -> Void) async {
        await shared.configure(build)
    }

    /// Configures this instance using a builder closure.
    ///
    /// - Parameter build: A closure that populates the builder with environments and settings.
    nonisolated public func configure(_ build: (inout PinGuardBuilder) -> Void) async {
        var builder = PinGuardBuilder()
        build(&builder)
        await update(configuration: builder.build())
    }

    /// Replaces the current configuration.
    ///
    /// - Parameter configuration: The new configuration to apply.
    public func update(configuration: PinGuardConfiguration) {
        self.configuration = configuration
    }

    /// Verifies a signed remote configuration and replaces the policy set of one environment.
    ///
    /// - Parameters:
    ///   - blob: The signed configuration blob received from the backend.
    ///   - verifier: The verifier that checks the blob's signature before anything is applied.
    ///   - environment: The environment to update; defaults to the active one.
    public func apply(remoteConfig blob: RemoteConfigBlob,
                      verifier: any RemoteConfigVerifier,
                      to environment: PinGuardEnvironment? = nil) throws {
        let target = environment ?? configuration.current
        let dispatcher = EventDispatcher(sinks: configuration.eventSinks)
        do {
            let policySet = try RemoteConfigDecoder(verifier: verifier).decode(blob)
            let mtls = configuration.environments[target]?.mtlsConfiguration
            configuration.environments[target] = PinGuardEnvironmentConfiguration(policySet: policySet,
                                                                                  mtlsConfiguration: mtls)
            dispatcher.emit(.remoteConfigApplied(environment: target.name))
        } catch {
            dispatcher.emit(.remoteConfigRejected(environment: target.name, error: String(describing: error)))
            throw error
        }
    }

    /// Evaluates server trust and pinning for the specified host using the active configuration.
    ///
    /// - Parameters:
    ///   - serverTrust: The SecTrust object representing the server's certificate chain.
    ///   - host: The hostname being evaluated.
    /// - Returns: The trust decision for the host.
    nonisolated public func evaluate(serverTrust: SecTrust, host: String) async -> TrustDecision {
        let snapshot = await currentConfiguration
        let evaluator = TrustEvaluator(policySet: snapshot.activePolicySet,
                                       eventSinks: snapshot.eventSinks,
                                       systemTrustEvaluator: systemTrustEvaluator)
        return await evaluator.evaluate(serverTrust: serverTrust, host: host)
    }
}
