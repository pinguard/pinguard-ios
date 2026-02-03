import Foundation

public final class PinGuardURLSessionDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
    private let pinGuard: PinGuard
    private let mtls: MTLSConfiguration?

    public init(pinGuard: PinGuard, mtls: MTLSConfiguration? = nil) {
        self.pinGuard = pinGuard
        self.mtls = mtls
    }

    @MainActor
    public convenience init(mtls: MTLSConfiguration? = nil) {
        self.init(pinGuard: .shared, mtls: mtls)
    }

    nonisolated public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handle(challenge: challenge, completionHandler: completionHandler)
    }

    nonisolated public func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handle(challenge: challenge, completionHandler: completionHandler)
    }

    nonisolated private func handle(
        challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        switch challenge.protectionSpace.authenticationMethod {
        case NSURLAuthenticationMethodServerTrust:
            guard let trust = challenge.protectionSpace.serverTrust else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            let host = challenge.protectionSpace.host
            let decision = pinGuard.evaluate(serverTrust: trust, host: host)
            if decision.isTrusted {
                completionHandler(.useCredential, URLCredential(trust: trust))
            } else {
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
            return
        case NSURLAuthenticationMethodClientCertificate:
            guard let mtls = mtls else {
                completionHandler(.rejectProtectionSpace, nil)
                return
            }
            let host = challenge.protectionSpace.host
            switch mtls.provider.clientIdentity(for: host) {
            case .success(let identity, let chain):
                let credential = URLCredential(identity: identity, certificates: chain, persistence: .forSession)
                PinGuardLogger.log(.mtlsIdentityUsed(host: host))
                completionHandler(.useCredential, credential)
            case .renewalRequired:
                PinGuardLogger.log(.mtlsIdentityMissing(host: host))
                mtls.onRenewalRequired?()
                completionHandler(.rejectProtectionSpace, nil)
            case .unavailable:
                PinGuardLogger.log(.mtlsIdentityMissing(host: host))
                completionHandler(.rejectProtectionSpace, nil)
            }
        default:
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

