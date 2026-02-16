//
//  ChallangeHandler.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation

public final class PinGuardURLSessionDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate {

    private let pinGuard: PinGuard
    private let mtls: MTLSConfiguration?

    public init(pinGuard: PinGuard, mtls: MTLSConfiguration? = nil) {
        self.pinGuard = pinGuard
        self.mtls = mtls
    }

    public convenience init(mtls: MTLSConfiguration? = nil) {
        self.init(pinGuard: .shared, mtls: mtls)
    }

    /// Handles session-level authentication challenges (server trust or client certificate).
    ///
    /// - Parameters:
    ///   - session: The URLSession receiving the challenge.
    ///   - challenge: The authentication challenge to handle.
    ///   - completionHandler: Closure to call with the disposition and optional credential.
    nonisolated public func urlSession(_ session: URLSession,
                                       didReceive challenge: URLAuthenticationChallenge,
                                       completionHandler: @escaping (URLSession.AuthChallengeDisposition,
                                                                     URLCredential?) -> Void) {
        handle(challenge: challenge, completionHandler: completionHandler)
    }

    /// Handles task-level authentication challenges (server trust or client certificate).
    ///
    /// - Parameters:
    ///   - session: The URLSession associated with the task.
    ///   - task: The task that received the challenge.
    ///   - challenge: The authentication challenge to handle.
    ///   - completionHandler: Closure to call with the disposition and optional credential.
    nonisolated public func urlSession(_ session: URLSession,
                                       task: URLSessionTask,
                                       didReceive challenge: URLAuthenticationChallenge,
                                       completionHandler: @escaping (URLSession.AuthChallengeDisposition,
                                                                     URLCredential?) -> Void) {
        handle(challenge: challenge, completionHandler: completionHandler)
    }

    /// Processes an authentication challenge and decides how to respond.
    ///
    /// - Parameters:
    ///   - challenge: The authentication challenge to process.
    ///   - completionHandler: Closure to call with the disposition and optional credential.
    nonisolated private func handle(challenge: URLAuthenticationChallenge,
                                    completionHandler: @escaping (URLSession.AuthChallengeDisposition,
                                                                  URLCredential?) -> Void) {
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
                emit(.mtlsIdentityUsed(host: host), host: host)
                completionHandler(.useCredential, credential)
            case .renewalRequired:
                emit(.mtlsIdentityMissing(host: host), host: host)
                mtls.onRenewalRequired?()
                completionHandler(.rejectProtectionSpace, nil)
            case .unavailable:
                emit(.mtlsIdentityMissing(host: host), host: host)
                completionHandler(.rejectProtectionSpace, nil)
            }
        default:
            completionHandler(.performDefaultHandling, nil)
        }
    }

    /// Emits a PinGuard event to logging and telemetry for the specified host.
    ///
    /// - Parameters:
    ///   - event: The event to emit.
    ///   - host: The host associated with the event.
    private func emit(_ event: PinGuardEvent, host: String) {
        PinGuardLogger.log(event)
        let config = pinGuard.currentConfiguration()
        config.telemetry?(event)
    }
}
