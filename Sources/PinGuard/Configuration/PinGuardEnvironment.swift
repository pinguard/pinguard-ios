//
//  PinGuardEnvironment.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 16.02.2026.
//

public struct PinGuardEnvironment: Hashable, Codable, ExpressibleByStringLiteral, Sendable {

    public let name: String

    public init(_ name: String) {
        self.name = name
    }

    public init(stringLiteral value: StringLiteralType) {
        self.name = value
    }

    public static let dev: PinGuardEnvironment = "dev"
    public static let uat: PinGuardEnvironment = "uat"
    public static let prod: PinGuardEnvironment = "prod"
}
