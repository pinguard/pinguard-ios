//
//  MTLSConfiguration.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

/// The mutual TLS settings of an environment: who supplies the identity and what to do when it expires.
public struct MTLSConfiguration: Sendable {

    /// The provider asked for a client identity on every client certificate challenge.
    public let provider: any ClientCertificateProvider

    /// Called when the provider reports that the identity must be renewed.
    public let onRenewalRequired: (@Sendable () -> Void)?

    public init(provider: any ClientCertificateProvider,
                onRenewalRequired: (@Sendable () -> Void)? = nil) {
        self.provider = provider
        self.onRenewalRequired = onRenewalRequired
    }
}
