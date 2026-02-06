//
//  HostMatcher.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation

public enum HostMatcher {

    /// Returns whether a host matches the given host pattern.
    ///
    /// - Parameters:
    ///   - pattern: The host pattern to match against (exact or wildcard).
    ///   - host: The hostname to test.
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
    ///   - suffix: The normalized suffix portion of the wildcard (e.g., "example.com").
    ///   - host: The normalized host to check.
    private static func wildcardMatches(suffix: String, host: String) -> Bool {
        let hostLabels = host.split(separator: ".")
        let suffixLabels = suffix.split(separator: ".")
        guard hostLabels.count == suffixLabels.count + 1 else {
            return false
        }

        return hostLabels.suffix(suffixLabels.count).elementsEqual(suffixLabels)
    }
}

struct PolicyResolver {

    private let policies: [HostPolicy]
    private let defaultPolicy: PinningPolicy?

    init(policySet: PolicySet) {
        self.policies = policySet.policies
        self.defaultPolicy = policySet.defaultPolicy
    }

    /// Resolves the most appropriate pinning policy for a given host.
    ///
    /// - Parameter host: The hostname for which to resolve policy.
    func resolve(host: String) -> PinningPolicy? {
        let normalized = HostPattern.normalizeHost(host)
        if normalized.isEmpty {
            return nil
        }

        if let exact = policies.first(where: { HostMatcher.matches($0.pattern, host: normalized)
            && isExact($0.pattern) }) {
            return exact.policy
        }
        let wildcardMatches = policies.filter {
            HostMatcher.matches($0.pattern, host: normalized)
        }
        if let mostSpecific = wildcardMatches.sorted(by: {
            wildcardSpecificity($0.pattern) > wildcardSpecificity($1.pattern)
        }).first {
            return mostSpecific.policy
        }
        return defaultPolicy
    }

    /// Indicates whether the provided pattern is an exact match pattern.
    ///
    /// - Parameter pattern: The host pattern to inspect.
    private func isExact(_ pattern: HostPattern) -> Bool {
        if case .exact = pattern {
            return true
        }

        return false
    }

    /// Returns a specificity score for comparing wildcard patterns.
    ///
    /// - Parameter pattern: The host pattern whose specificity should be measured.
    private func wildcardSpecificity(_ pattern: HostPattern) -> Int {
        switch pattern {
        case .exact(let value):
            return value.count + 1000
        case .wildcard(let value):
            return value.count
        }
    }
}
