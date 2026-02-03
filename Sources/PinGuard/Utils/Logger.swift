import Foundation
import os

enum PinGuardEvent: Equatable, Sendable {

    case policyMissing(host: String)
    case systemTrustEvaluated(host: String, isTrusted: Bool)
    case systemTrustFailed(host: String, error: String?)
    case systemTrustFailedPermissive(host: String)
    case chainSummary(host: String, summary: ChainSummary)
    case pinMatched(host: String, pins: [Pin])
    case pinMismatch(host: String)
    case pinMismatchAllowedByFallback(host: String)
    case pinMismatchPermissive(host: String)
    case pinSetEmpty(host: String)
    case mtlsIdentityUsed(host: String)
    case mtlsIdentityMissing(host: String)
}

// swiftlint:disable all
struct PinGuardLogger {

    static let subsystem = "PinGuard"
    static let logger = Logger(subsystem: subsystem, category: "core")

    static func log(_ event: PinGuardEvent) {
        switch event {
        case .policyMissing(let host):
            logger.error("Policy missing for host: \(host, privacy: .public)")
        case .systemTrustEvaluated(let host, let isTrusted):
            logger.debug("System trust evaluated: \(isTrusted, privacy: .public) for \(host, privacy: .public)")
        case .systemTrustFailed(let host, let error):
            logger.error("System trust failed for \(host, privacy: .public) error: \(error ?? "unknown", privacy: .public)")
        case .systemTrustFailedPermissive(let host):
            logger.warning("System trust failed but permissive for \(host, privacy: .public)")
        case .chainSummary(let host, let summary):
            logger.debug("Chain summary for \(host, privacy: .public) CN=\(summary.leafCommonName ?? "-", privacy: .public) issuer=\(summary.issuerCommonName ?? "-", privacy: .public) sanCount=\(summary.sanCount, privacy: .public)")
        case .pinMatched(let host, let pins):
            logger.info("Pin matched for \(host, privacy: .public) pins=\(pins.count, privacy: .public)")
        case .pinMismatch(let host):
            logger.error("Pin mismatch for \(host, privacy: .public)")
        case .pinMismatchAllowedByFallback(let host):
            logger.warning("Pin mismatch allowed by fallback for \(host, privacy: .public)")
        case .pinMismatchPermissive(let host):
            logger.warning("Pin mismatch allowed by permissive for \(host, privacy: .public)")
        case .pinSetEmpty(let host):
            logger.error("Pin set empty for \(host, privacy: .public)")
        case .mtlsIdentityUsed(let host):
            logger.info("mTLS identity used for \(host, privacy: .public)")
        case .mtlsIdentityMissing(let host):
            logger.error("mTLS identity missing for \(host, privacy: .public)")
        }
    }
}
// swiftlint:enable all
