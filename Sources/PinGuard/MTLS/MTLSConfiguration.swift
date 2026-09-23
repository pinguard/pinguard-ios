//
//  MTLSConfiguration.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

public struct MTLSConfiguration: Sendable {

    public let provider: any ClientCertificateProvider
    public let onRenewalRequired: (@Sendable () -> Void)?

    public init(provider: any ClientCertificateProvider,
                onRenewalRequired: (@Sendable () -> Void)? = nil) {
        self.provider = provider
        self.onRenewalRequired = onRenewalRequired
    }
}
