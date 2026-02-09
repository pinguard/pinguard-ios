//
//  MTLSConfiguration.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation
import Security

public struct MTLSConfiguration: Sendable {

    public let provider: ClientCertificateProvider
    public let onRenewalRequired: (@Sendable () -> Void)?

    public init(provider: ClientCertificateProvider,
                onRenewalRequired: (@Sendable () -> Void)? = nil) {
        self.provider = provider
        self.onRenewalRequired = onRenewalRequired
    }
}

public protocol ClientCertificateProvider: Sendable {

    /// Provides a client identity to use for mTLS with the specified host.
    ///
    /// - Parameter host: The hostname requesting a client identity.
    func clientIdentity(for host: String) -> ClientIdentityResult
}

/// The result of requesting a client identity for mutual TLS (mTLS).
///
/// `ClientIdentityResult` captures whether a usable identity is available, needs renewal,
/// or is unavailable. On success, it includes the `SecIdentity` and the accompanying
/// certificate chain to present to the server.
public enum ClientIdentityResult {

    /// A client identity and its certificate chain were successfully retrieved.
    ///
    /// - Parameters:
    ///   - identity: The client identity (private key and certificate).
    ///   - certificateChain: The certificate chain to present with the identity.
    case success(identity: SecIdentity, certificateChain: [SecCertificate])

    /// A client identity is required but must be renewed or re-provisioned.
    case renewalRequired

    /// No client identity is available for the request.
    case unavailable
}
