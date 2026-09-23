//
//  PinGuardURLSessionDelegate.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation

public final class PinGuardURLSessionDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate {

    private let pinGuard: PinGuard

    public init(pinGuard: PinGuard = .shared) {
        self.pinGuard = pinGuard
    }

    /// Handles session-level authentication challenges.
    ///
    /// - Parameters:
    ///   - session: The URLSession receiving the challenge.
    ///   - challenge: The authentication challenge to handle.
    /// - Returns: The disposition and optional credential for the challenge.
    public func urlSession(_ session: URLSession,
                           didReceive challenge: URLAuthenticationChallenge) async
        -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        await handle(challenge: challenge)
    }

    /// Handles task-level authentication challenges.
    ///
    /// - Parameters:
    ///   - session: The URLSession associated with the task.
    ///   - task: The task that received the challenge.
    ///   - challenge: The authentication challenge to handle.
    /// - Returns: The disposition and optional credential for the challenge.
    public func urlSession(_ session: URLSession,
                           task: URLSessionTask,
                           didReceive challenge: URLAuthenticationChallenge) async
        -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        await handle(challenge: challenge)
    }

    /// Routes a challenge to server trust or client certificate handling.
    ///
    /// - Parameter challenge: The authentication challenge to process.
    /// - Returns: The disposition and optional credential for the challenge.
    private func handle(challenge: URLAuthenticationChallenge) async
        -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        let host = challenge.protectionSpace.host
        switch challenge.protectionSpace.authenticationMethod {
        case NSURLAuthenticationMethodServerTrust:
            guard let trust = challenge.protectionSpace.serverTrust else {
                return (.cancelAuthenticationChallenge, nil)
            }

            let decision = await pinGuard.evaluate(serverTrust: trust, host: host)
            guard decision.isTrusted else {
                return (.cancelAuthenticationChallenge, nil)
            }

            return (.useCredential, URLCredential(trust: trust))
        case NSURLAuthenticationMethodClientCertificate:
            return await handleClientCertificate(host: host)
        default:
            return (.performDefaultHandling, nil)
        }
    }

    /// Resolves the client identity for the host from the active configuration.
    ///
    /// - Parameter host: The hostname requesting a client certificate.
    /// - Returns: The disposition and optional credential for the challenge.
    private func handleClientCertificate(host: String) async
        -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        let configuration = await pinGuard.currentConfiguration
        let dispatcher = EventDispatcher(sinks: configuration.eventSinks)
        guard let mtls = configuration.activeMTLS else {
            return (.rejectProtectionSpace, nil)
        }

        switch await mtls.provider.clientIdentity(for: host) {
        case .success(let identity, let chain):
            let credential = URLCredential(identity: identity, certificates: chain, persistence: .forSession)
            dispatcher.emit(.mtlsIdentityUsed(host: host))
            return (.useCredential, credential)
        case .renewalRequired:
            dispatcher.emit(.mtlsIdentityMissing(host: host))
            mtls.onRenewalRequired?()
            return (.rejectProtectionSpace, nil)
        case .unavailable:
            dispatcher.emit(.mtlsIdentityMissing(host: host))
            return (.rejectProtectionSpace, nil)
        }
    }
}
