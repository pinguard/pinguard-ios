//
//  PolicyResolver.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

struct PolicyResolver: Sendable {

    private let policies: [HostPolicy]
    private let defaultPolicy: PinningPolicy?

    init(policySet: PolicySet) {
        self.policies = policySet.policies
        self.defaultPolicy = policySet.defaultPolicy
    }

    /// Resolves the most appropriate pinning policy for a given host.
    ///
    /// - Parameter host: The hostname for which to resolve policy.
    /// - Returns: The matching policy, the default policy, or `nil` when none applies.
    func resolve(host: String) -> PinningPolicy? {
        let normalized = HostPattern.normalizeHost(host)
        guard !normalized.isEmpty else {
            return nil
        }

        let matching = policies.filter { HostMatcher.matches($0.pattern, host: normalized) }
        if let exact = matching.first(where: { $0.pattern.isExact }) {
            return exact.policy
        }
        if let mostSpecific = matching.max(by: { $0.pattern.specificity < $1.pattern.specificity }) {
            return mostSpecific.policy
        }
        return defaultPolicy
    }
}
