//
//  HostMatcher.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

public enum HostMatcher {

    /// Returns whether a host matches the given host pattern.
    ///
    /// - Parameters:
    ///   - pattern: The host pattern to match against (exact or wildcard).
    ///   - host: The hostname to test.
    /// - Returns: `true` when the host satisfies the pattern.
    public static func matches(_ pattern: HostPattern, host: String) -> Bool {
        let normalizedHost = HostPattern.normalizeHost(host)
        guard !normalizedHost.isEmpty else {
            return false
        }

        switch pattern {
        case .exact(let value):
            return HostPattern.normalizeHost(value) == normalizedHost
        case .wildcard(let suffix):
            return wildcardMatches(suffix: HostPattern.normalizeHost(suffix), host: normalizedHost)
        }
    }

    /// Checks if a hostname matches a wildcard pattern by suffix comparison.
    ///
    /// - Parameters:
    ///   - suffix: The normalized suffix portion of the wildcard (e.g. "example.com").
    ///   - host: The normalized host to check.
    /// - Returns: `true` when the host has exactly one extra label in front of the suffix.
    private static func wildcardMatches(suffix: String, host: String) -> Bool {
        let hostLabels = host.split(separator: ".")
        let suffixLabels = suffix.split(separator: ".")
        guard hostLabels.count == suffixLabels.count + 1 else {
            return false
        }

        return hostLabels.suffix(suffixLabels.count).elementsEqual(suffixLabels)
    }
}
