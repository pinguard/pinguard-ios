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

    private let lock = NSLock()
    private var configuration: PinGuardConfiguration

    private init() {
        self.configuration = PinGuardConfiguration(environments: [:], current: .prod)
    }

    /// Configures the shared PinGuard instance using a builder closure.
    ///
    /// - Parameter build: A closure that populates the builder with environments and settings.
    public static func configure(_ build: (inout PinGuardBuilder) -> Void) {
        var builder = PinGuardBuilder()
        build(&builder)
        let config = PinGuardConfiguration(environments: builder.environments,
                                           current: builder.current,
                                           telemetry: builder.telemetry)
        shared.update(configuration: config)
    }

    /// Updates the current configuration in a thread-safe manner.
    ///
    /// - Parameter configuration: The new configuration to apply.
    public func update(configuration: PinGuardConfiguration) {
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
    public func currentConfiguration() -> PinGuardConfiguration {
        lock.lock()
        defer {
            lock.unlock()
        }
        return configuration
    }
}
