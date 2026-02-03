import Foundation
import Security

struct MTLSConfiguration: Sendable {

    let provider: ClientCertificateProvider
    let onRenewalRequired: (@Sendable () -> Void)?

    init(provider: ClientCertificateProvider,
         onRenewalRequired: (@Sendable () -> Void)? = nil) {
        self.provider = provider
        self.onRenewalRequired = onRenewalRequired
    }
}

protocol ClientCertificateProvider: Sendable {

    func clientIdentity(for host: String) -> ClientIdentityResult
}

enum ClientIdentityResult {

    case success(identity: SecIdentity, certificateChain: [SecCertificate])
    case renewalRequired
    case unavailable
}
