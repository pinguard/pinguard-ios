//
//  PinGuardEnvironment.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 16.02.2026.
//

/// A named deployment environment such as development, UAT or production.
public struct PinGuardEnvironment: Hashable, Codable, ExpressibleByStringLiteral, Sendable {

    /// The identifier of the environment, also used in events.
    public let name: String

    public init(_ name: String) {
        self.name = name
    }

    public init(stringLiteral value: StringLiteralType) {
        self.name = value
    }

    /// The development environment.
    public static let dev: PinGuardEnvironment = "dev"

    /// The user acceptance testing environment.
    public static let uat: PinGuardEnvironment = "uat"

    /// The production environment, selected by default.
    public static let prod: PinGuardEnvironment = "prod"
}
