//
//  PinGuardEnvironment.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 16.02.2026.

/// A lightweight, hashable identifier that represents a runtime environment
/// for PinGuard (for example, development, UAT, or production).
///
/// You can create custom environments using string literals or by calling
/// the initializer directly. Common presets are provided via static
/// properties such as `dev`, `uat`, and `prod`.
///
/// Example:
/// ```swift
/// let environment: PinGuardEnvironment = "staging"
/// // or
/// let environment = PinGuardEnvironment("staging")
/// ```
public struct PinGuardEnvironment: Hashable, Codable, ExpressibleByStringLiteral, Sendable {

    /// The string identifier for the environment (e.g., "dev", "uat", "prod").
    public let name: String

    /// Creates a `PinGuardEnvironment` with the provided name.
    ///
    /// - Parameter name: The identifier for the environment (e.g., "dev", "uat", "prod").
    public init(_ name: String) {
        self.name = name
    }

    /// Initializes a `PinGuardEnvironment` from a string literal.
    ///
    /// - Parameter value: The string literal used as the environment name.
    public init(stringLiteral value: StringLiteralType) {
        self.name = value
    }

    /// A preset environment representing development.
    public static let dev: PinGuardEnvironment = "dev"
    /// A preset environment representing user acceptance testing (UAT).
    public static let uat: PinGuardEnvironment = "uat"
    /// A preset environment representing production.
    public static let prod: PinGuardEnvironment = "prod"
}

/// Associates a `PolicySet` and optional mutual TLS (mTLS) settings with a
/// specific environment. Use this type to define how certificate pinning and
/// client authentication should behave per environment.
public struct PinGuardEnvironmentConfiguration: Sendable {

    /// The set of certificate pinning policies that apply in this environment.
    public let policySet: PolicySet
    /// Optional configuration for enabling mutual TLS (client authentication).
    /// Provide a value to require client certificates; `nil` disables mTLS.
    public let mtlsConfiguration: MTLSConfiguration?

    /// Initializes a `PinGuardEnvironmentConfiguration` with a policy set and optional mTLS configuration.
    ///
    /// - Parameters:
    ///   - policySet: The set of certificate pinning policies for this environment.
    ///   - mtlsConfiguration: Optional mutual TLS configuration to enable client authentication.
    public init(policySet: PolicySet,
                mtlsConfiguration: MTLSConfiguration? = nil) {
        self.policySet = policySet
        self.mtlsConfiguration = mtlsConfiguration
    }
}
