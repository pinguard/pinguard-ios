//
//  PinGuard.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation
import Security

public final class PinGuard: @unchecked Sendable {

    public static let shared = PinGuard()

    public struct Configuration: Sendable {

        public struct Environment: Hashable, Codable, ExpressibleByStringLiteral, Sendable {
            public let name: String

            public init(_ name: String) {
                self.name = name
            }

            public init(stringLiteral value: StringLiteralType) {
                self.name = value
            }

            public static let dev: Environment = "dev"
            public static let uat: Environment = "uat"
            public static let prod: Environment = "prod"
        }

        public struct EnvironmentConfiguration: Sendable {

            public let policySet: PolicySet
            public let mtlsConfiguration: MTLSConfiguration?

            public init(policySet: PolicySet,
                        mtlsConfiguration: MTLSConfiguration? = nil) {
                self.policySet = policySet
                self.mtlsConfiguration = mtlsConfiguration
            }
        }

        public var environments: [Environment: EnvironmentConfiguration]
        public var current: Environment
        public var telemetry: (@Sendable (PinGuardEvent) -> Void)?

        public init(environments: [Environment: EnvironmentConfiguration],
                    current: Environment,
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

    public struct Builder {

        private(set) var environments: [Configuration.Environment: Configuration.EnvironmentConfiguration] = [:]
        private(set) var current: Configuration.Environment = .prod
        private(set) var telemetry: (@Sendable (PinGuardEvent) -> Void)?

        /// Adds an environment configuration to the builder.
        ///
        /// - Parameters:
        ///   - env: The environment identifier to configure.
        ///   - policySet: The pinning policy set to use for this environment.
        ///   - mtls: Optional mTLS configuration for this environment.
        public mutating func environment(_ env: Configuration.Environment,
                                         policySet: PolicySet,
                                         mtls: MTLSConfiguration? = nil) {
            environments[env] = Configuration.EnvironmentConfiguration(policySet: policySet, mtlsConfiguration: mtls)
        }

        /// Selects the active environment for the resulting configuration.
        ///
        /// - Parameter env: The environment to set as current.
        public mutating func selectEnvironment(_ env: Configuration.Environment) {
            current = env
        }

        /// Sets a telemetry callback to receive emitted PinGuard events.
        ///
        /// - Parameter handler: A closure invoked for each event.
        public mutating func telemetry(_ handler: @Sendable @escaping (PinGuardEvent) -> Void) {
            telemetry = handler
        }
    }

    private let lock = NSLock()
    private var configuration: Configuration

    private init() {
        self.configuration = Configuration(environments: [:], current: .prod)
    }

    /// Configures the shared PinGuard instance using a builder closure.
    ///
    /// - Parameter build: A closure that populates the builder with environments and settings.
    public static func configure(_ build: (inout Builder) -> Void) {
        var builder = Builder()
        build(&builder)
        let config = Configuration(environments: builder.environments,
                                   current: builder.current,
                                   telemetry: builder.telemetry)
        shared.update(configuration: config)
    }

    /// Updates the current configuration in a thread-safe manner.
    ///
    /// - Parameter configuration: The new configuration to apply.
    public func update(configuration: Configuration) {
        lock.lock()
        defer {
            lock.unlock()
        }
        self.configuration = configuration
    }

    /// Evaluates server trust and pinning for the specified host.
    ///
    /// - Parameters:
    ///   - serverTrust: The SecTrust object representing the server's certificate chain.
    ///   - host: The hostname being evaluated.
    public func evaluate(serverTrust: SecTrust, host: String) -> TrustDecision {
        let config = currentConfiguration()
        let evaluator = TrustEvaluator(policySet: config.activePolicySet) { event in
            PinGuardLogger.log(event)
            config.telemetry?(event)
        }
        return evaluator.evaluate(serverTrust: serverTrust, host: host)
    }

    /// Returns the current PinGuard configuration.
    public func currentConfiguration() -> Configuration {
        lock.lock()
        defer {
            lock.unlock()
        }
        return configuration
    }
}
