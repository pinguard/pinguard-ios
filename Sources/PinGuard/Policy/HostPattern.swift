//
//  HostPattern.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation

public enum HostPattern: Hashable, Codable, Sendable {

    /// Matches only the exact hostname value.
    case exact(String)

    /// Matches any single-label subdomain of the given suffix (e.g. *.example.com).
    case wildcard(String)

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        self = HostPattern.parse(try container.decode(String.self))
    }

    public var rawValue: String {
        switch self {
        case .exact(let value):
            return value
        case .wildcard(let value):
            return "*." + value
        }
    }

    var isExact: Bool {
        if case .exact = self {
            return true
        }

        return false
    }

    var specificity: Int {
        switch self {
        case .exact(let value):
            return value.count
        case .wildcard(let value):
            return value.count
        }
    }

    /// Encodes the pattern as its single string form, e.g. `*.example.com`.
    ///
    /// - Parameter encoder: The encoder to write the string into.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    /// Parses a host pattern string into a HostPattern, interpreting "*." as a wildcard.
    ///
    /// - Parameter pattern: The host pattern string to parse.
    /// - Returns: The parsed pattern.
    public static func parse(_ pattern: String) -> HostPattern {
        let normalized = HostPattern.normalizeHost(pattern)
        if normalized.hasPrefix("*.") {
            return .wildcard(String(normalized.dropFirst(2)))
        }
        return .exact(normalized)
    }

    /// Normalizes a host for matching by lowercasing and trimming leading/trailing dots.
    ///
    /// - Parameter host: The host string to normalize.
    /// - Returns: The normalized host string.
    static func normalizeHost(_ host: String) -> String {
        host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
    }
}
