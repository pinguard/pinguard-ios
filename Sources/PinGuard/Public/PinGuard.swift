import Foundation
import Security

@MainActor
final class PinGuard {

    static let shared = PinGuard()

    struct Configuration {

        struct Environment: Hashable, Codable, ExpressibleByStringLiteral, Sendable {
            let name: String

            init(_ name: String) {
                self.name = name
            }

            init(stringLiteral value: StringLiteralType) {
                self.name = value
            }

            static let dev: Environment = "dev"
            static let uat: Environment = "uat"
            static let prod: Environment = "prod"
        }

        struct EnvironmentConfiguration {

            let policySet: PolicySet
            let mtlsConfiguration: MTLSConfiguration?

            init(policySet: PolicySet, mtlsConfiguration: MTLSConfiguration? = nil) {
                self.policySet = policySet
                self.mtlsConfiguration = mtlsConfiguration
            }
        }

        var environments: [Environment: EnvironmentConfiguration]
        var current: Environment
        var telemetry: ((PinGuardEvent) -> Void)?

        init(environments: [Environment: EnvironmentConfiguration],
             current: Environment,
             telemetry: ((PinGuardEvent) -> Void)? = nil) {
            self.environments = environments
            self.current = current
            self.telemetry = telemetry
        }

        var activePolicySet: PolicySet {
            environments[current]?.policySet ?? PolicySet(policies: [])
        }

        var activeMTLS: MTLSConfiguration? {
            environments[current]?.mtlsConfiguration
        }
    }

    struct Builder {

        private(set) var environments: [Configuration.Environment: Configuration.EnvironmentConfiguration] = [:]
        private(set) var current: Configuration.Environment = .prod
        private(set) var telemetry: ((PinGuardEvent) -> Void)?

        mutating func environment(_ env: Configuration.Environment,
                                  policySet: PolicySet,
                                  mtls: MTLSConfiguration? = nil) {
            environments[env] = Configuration.EnvironmentConfiguration(policySet: policySet, mtlsConfiguration: mtls)
        }

        mutating func selectEnvironment(_ env: Configuration.Environment) {
            current = env
        }

        mutating func telemetry(_ handler: @escaping (PinGuardEvent) -> Void) {
            telemetry = handler
        }
    }

    private let lock = NSLock()
    nonisolated(unsafe) private var configuration: Configuration

    private init() {
        self.configuration = Configuration(environments: [:], current: .prod)
    }

    static func configure(_ build: (inout Builder) -> Void) {
        var builder = Builder()
        build(&builder)
        let config = Configuration(environments: builder.environments,
                                   current: builder.current,
                                   telemetry: builder.telemetry)
        shared.update(configuration: config)
    }

    func update(configuration: Configuration) {
        lock.lock()
        self.configuration = configuration
        lock.unlock()
    }

    nonisolated func evaluate(serverTrust: SecTrust, host: String) -> TrustDecision {
        let config = currentConfiguration()
        let evaluator = TrustEvaluator(policySet: config.activePolicySet) { event in
            PinGuardLogger.log(event)
            config.telemetry?(event)
        }
        return evaluator.evaluate(serverTrust: serverTrust, host: host)
    }

    nonisolated func currentConfiguration() -> Configuration {
        lock.lock()
        let config = configuration
        lock.unlock()
        return config
    }
}

enum RemoteConfigSignature: Codable, Equatable, Sendable {

    case hmacSHA256(secretID: String)
    case publicKey(keyID: String)
}

struct RemoteConfigBlob: Codable, Equatable, Sendable {

    let payload: Data
    let signature: Data
    let signatureType: RemoteConfigSignature
}

protocol RemoteConfigVerifier {

    func verify(blob: RemoteConfigBlob) -> Bool
}

enum RemoteConfigThreatModel {

    static let unsignedConfigWarning =
        "Unsigned remote configuration is insecure; it allows a network attacker to disable pinning."
}
