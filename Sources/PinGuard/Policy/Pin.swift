//
//  Pin.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

private enum PinCodingKey: String, CodingKey {

    case type
    case hash
    case role
    case scope
}

public struct Pin: Hashable, Codable, Sendable {

    public let type: PinType
    public let hash: String
    public let role: PinRole
    public let scope: PinScope

    public init(type: PinType,
                hash: String,
                role: PinRole = .primary,
                scope: PinScope = .any) {
        self.type = type
        self.hash = hash
        self.role = role
        self.scope = scope
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: PinCodingKey.self)
        self.type = try container.decode(PinType.self, forKey: .type)
        self.hash = try container.decode(String.self, forKey: .hash)
        self.role = try container.decodeIfPresent(PinRole.self, forKey: .role) ?? .primary
        self.scope = try container.decodeIfPresent(PinScope.self, forKey: .scope) ?? .any
    }

    /// Encodes every field of the pin.
    ///
    /// - Parameter encoder: The encoder to write the fields into.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: PinCodingKey.self)
        try container.encode(type, forKey: .type)
        try container.encode(hash, forKey: .hash)
        try container.encode(role, forKey: .role)
        try container.encode(scope, forKey: .scope)
    }
}
