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

    func clientIdentity(for host: String) -> ClientIdentityResult
}

public enum ClientIdentityResult {

    case success(identity: SecIdentity, certificateChain: [SecCertificate])
    case renewalRequired
    case unavailable
}
