# ``PinGuard/ClientCertificateProvider``

## Overview

A provider answers one question: which identity should the app present to this host right now. ``StaticClientCertificateProvider`` answers it by loading from a fixed ``ClientCertificateSource``. Write your own when identities are enrolled, refreshed or chosen per host:

```swift
struct EnrolledIdentityProvider: ClientCertificateProvider {

    let store: IdentityStore

    func clientIdentity(for host: String) async -> ClientIdentityResult {
        guard let identity = await store.currentIdentity() else {
            return .unavailable
        }
        return .success(identity: identity.secIdentity, certificateChain: identity.chain)
    }
}
```

Return ``ClientIdentityResult/renewalRequired`` when you know the identity exists but can no longer be used. PinGuard then calls ``MTLSConfiguration/onRenewalRequired`` so your app can react.

## Topics

### Supplying an identity

- ``clientIdentity(for:)``
