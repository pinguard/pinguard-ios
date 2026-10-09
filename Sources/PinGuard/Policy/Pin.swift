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

/// A single expected hash together with what it hashes, its role and where in the chain it may match.
public struct Pin: Hashable, Codable, Sendable {

    /// What the hash was computed from: the public key, the certificate or a CA certificate.
    public let type: PinType

    /// The Base64 encoded SHA-256 digest to compare against.
    public let hash: String

    /// Whether this is the primary pin or the backup kept for key rotation.
    public let role: PinRole

    /// The chain position this pin is allowed to match.
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
