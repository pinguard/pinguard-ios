//
//  PinGuardEvent+Summary.swift
//  Example
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import PinGuard

extension PinGuardEvent {

    var summary: String {
        switch self {
        case .policyMissing(let host):
            return "No policy for \(host)"
        case .systemTrustEvaluated(let host, let isTrusted):
            return "System trust for \(host): \(isTrusted ? "ok" : "failed")"
        case .systemTrustFailed(let host, let error):
            return "System trust failed for \(host): \(error ?? "unknown")"
        case .systemTrustFailedPermissive(let host):
            return "System trust failed for \(host), allowed by permissive policy"
        case .chainSummary(let host, let summary):
            return "Chain for \(host): \(summary.leafCommonName ?? "-") SANs=\(summary.sanCount)"
        case .pinMatched(let host, let pins):
            return "Pin matched for \(host): \(pins.map(\.role.rawValue).joined(separator: ", "))"
        case .pinMismatch(let host):
            return "Pin mismatch for \(host)"
        case .pinMismatchAllowedByFallback(let host):
            return "Pin mismatch for \(host), allowed because system trust passed"
        case .pinMismatchPermissive(let host):
            return "Pin mismatch for \(host), allowed by permissive policy"
        case .pinSetEmpty(let host):
            return "No pins configured for \(host)"
        case .mtlsIdentityUsed(let host):
            return "Client certificate sent to \(host)"
        case .mtlsIdentityMissing(let host):
            return "Client certificate missing for \(host)"
        case .remoteConfigApplied(let environment):
            return "Remote config applied to \(environment)"
        case .remoteConfigRejected(let environment, let error):
            return "Remote config rejected for \(environment): \(error)"
        }
    }
}
