//
//  OSLogEventSink.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import os

public struct OSLogEventSink: PinGuardEventSink {

    private let logger: Logger

    public init(subsystem: String = "PinGuard", category: String = "core") {
        self.logger = Logger(subsystem: subsystem, category: category)
    }

    /// Logs the event with a severity that matches its meaning.
    ///
    /// - Parameter event: The event that was emitted.
    public func receive(_ event: PinGuardEvent) {
        switch event {
        case .policyMissing(let host):
            logger.error("[PinGuard] Policy missing for host: \(host, privacy: .public)")
        case .systemTrustEvaluated(let host, let isTrusted):
            logger.debug("""
                [PinGuard] System trust evaluated: \(isTrusted, privacy: .public) for \(host, privacy: .public)
                """)
        case .systemTrustFailed(let host, let error):
            logger.error("""
                [PinGuard] System trust failed for \(host, privacy: .public) \
                error: \(error ?? "unknown", privacy: .public)
                """)
        case .systemTrustFailedPermissive(let host):
            logger.warning("[PinGuard] System trust failed but permissive for \(host, privacy: .public)")
        case .chainSummary(let host, let summary):
            logger.debug("""
                [PinGuard] Chain summary for \(host, privacy: .public) \
                CN=\(summary.leafCommonName ?? "-", privacy: .public) \
                issuer=\(summary.issuerCommonName ?? "-", privacy: .public) \
                sanCount=\(summary.sanCount, privacy: .public)
                """)
        case .pinMatched(let host, let pins):
            logger.info("[PinGuard] Pin matched for \(host, privacy: .public) pins=\(pins.count, privacy: .public)")
        case .pinMismatch(let host):
            logger.error("[PinGuard] Pin mismatch for \(host, privacy: .public)")
        case .pinMismatchAllowedByFallback(let host):
            logger.warning("[PinGuard] Pin mismatch allowed by fallback for \(host, privacy: .public)")
        case .pinMismatchPermissive(let host):
            logger.warning("[PinGuard] Pin mismatch allowed by permissive for \(host, privacy: .public)")
        case .pinSetEmpty(let host):
            logger.error("[PinGuard] Pin set empty for \(host, privacy: .public)")
        case .mtlsIdentityUsed(let host):
            logger.info("[PinGuard] mTLS identity used for \(host, privacy: .public)")
        case .mtlsIdentityMissing(let host):
            logger.error("[PinGuard] mTLS identity missing for \(host, privacy: .public)")
        case .remoteConfigApplied(let environment):
            logger.info("[PinGuard] Remote config applied to \(environment, privacy: .public)")
        case .remoteConfigRejected(let environment, let error):
            logger.error("""
                [PinGuard] Remote config rejected for \(environment, privacy: .public) \
                error: \(error, privacy: .public)
                """)
        }
    }
}
