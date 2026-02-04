import Foundation
import Security

@MainActor
public final class PinGuard {

    public static let shared = PinGuard()

    public struct Configuration {

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

        public struct EnvironmentConfiguration {

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
        public var telemetry: ((PinGuardEvent) -> Void)?

        public init(environments: [Environment: EnvironmentConfiguration],
                    current: Environment,
                    telemetry: ((PinGuardEvent) -> Void)? = nil) {
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
        private(set) var telemetry: ((PinGuardEvent) -> Void)?

        public mutating func environment(_ env: Configuration.Environment,
                                         policySet: PolicySet,
                                         mtls: MTLSConfiguration? = nil) {
            environments[env] = Configuration.EnvironmentConfiguration(policySet: policySet, mtlsConfiguration: mtls)
        }

        public mutating func selectEnvironment(_ env: Configuration.Environment) {
            current = env
        }

        public mutating func telemetry(_ handler: @escaping (PinGuardEvent) -> Void) {
            telemetry = handler
        }
    }

    private let lock = NSLock()
    nonisolated(unsafe) private var configuration: Configuration

    private init() {
        self.configuration = Configuration(environments: [:], current: .prod)
    }

    public static func configure(_ build: (inout Builder) -> Void) {
        var builder = Builder()
        build(&builder)
        let config = Configuration(environments: builder.environments,
                                   current: builder.current,
                                   telemetry: builder.telemetry)
        shared.update(configuration: config)
    }

    public func update(configuration: Configuration) {
        lock.lock()
        self.configuration = configuration
        lock.unlock()
    }

    nonisolated public func evaluate(serverTrust: SecTrust, host: String) -> TrustDecision {
        let config = currentConfiguration()
        let evaluator = TrustEvaluator(policySet: config.activePolicySet) { event in
            PinGuardLogger.log(event)
            config.telemetry?(event)
        }
        return evaluator.evaluate(serverTrust: serverTrust, host: host)
    }

    nonisolated public func currentConfiguration() -> Configuration {
        lock.lock()
        let config = configuration
        lock.unlock()
        return config
    }
}
