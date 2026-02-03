import Foundation

enum HostMatcher {

    static func matches(_ pattern: HostPattern, host: String) -> Bool {
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

    func isExact(_ pattern: HostPattern) -> Bool {
        if case .exact = pattern {
            return true
        }

        return false
    }

    private func wildcardSpecificity(_ pattern: HostPattern) -> Int {
        switch pattern {
        case .exact(let value):
            return value.count + 1000
        case .wildcard(let value):
            return value.count
        }
    }
}
