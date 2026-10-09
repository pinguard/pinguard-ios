# Mutual TLS

Present a client certificate when the server asks for one.

## Overview

Some backends authenticate the app as well as the user: the server asks for a client certificate during the TLS handshake and refuses the connection without it. PinGuard handles that challenge next to the server trust challenge, using an ``MTLSConfiguration`` attached to the environment.

## Attaching a client identity

An ``MTLSConfiguration`` has two parts: a ``ClientCertificateProvider`` that supplies the identity, and an optional closure PinGuard calls when the identity needs renewal. The simplest provider loads a fixed identity from PKCS12 data:

```swift
let provider = StaticClientCertificateProvider(
    source: .pkcs12(data: p12Data, password: "p12-password")
)

let mtls = MTLSConfiguration(provider: provider) {
    // The identity must be renewed. Start your re enrolment flow here.
}

builder.environment(.prod, policySet: policySet, mtls: mtls)
```

``ClientCertificateSource/keychain(identityTag:)`` loads the identity from the data protection keychain instead, by its application tag:

```swift
let provider = StaticClientCertificateProvider(
    source: .keychain(identityTag: Data("com.example.client-identity".utf8))
)
```

The keychain lookup returns the identity together with its own certificate. If your server needs the intermediate certificates as well, use the PKCS12 source, which carries the full chain.

## What happens on a challenge

When the server asks for a client certificate, ``PinGuardURLSessionDelegate`` looks up the mTLS settings of the active environment and asks the provider for an identity:

- ``ClientIdentityResult/success(identity:certificateChain:)``: the identity is wrapped in a `URLCredential` with `.forSession` persistence and presented. PinGuard emits `mtlsIdentityUsed`.
- ``ClientIdentityResult/renewalRequired``: PinGuard emits `mtlsIdentityMissing`, calls `onRenewalRequired` and rejects the protection space. The request fails.
- ``ClientIdentityResult/unavailable``: PinGuard emits `mtlsIdentityMissing` and rejects the protection space.

If the active environment has no ``MTLSConfiguration`` at all, the protection space is rejected without an event. Note that the settings are read on every challenge, so switching environments takes effect immediately and no new session is needed.

## Writing your own provider

``StaticClientCertificateProvider`` reads from its source on every challenge and never decides that renewal is required. When the identity comes from somewhere else, for example an enrolment service or a certificate you refresh periodically, conform to ``ClientCertificateProvider`` yourself:

```swift
struct EnrolledIdentityProvider: ClientCertificateProvider {

    let store: IdentityStore

    func clientIdentity(for host: String) async -> ClientIdentityResult {
        guard let identity = await store.currentIdentity() else {
            return .unavailable
        }
        guard identity.expiresAt > .now else {
            return .renewalRequired
        }
        return .success(identity: identity.secIdentity, certificateChain: identity.chain)
    }
}
```

The method is `async`, so fetching or unlocking the identity is fine. The `host` argument lets one provider serve different identities to different servers.

## Loading identities yourself

``ClientCertificateLoader`` is the piece ``StaticClientCertificateProvider`` uses. It is public so you can reuse it, for example to validate a PKCS12 file at enrolment time before storing it:

```swift
switch ClientCertificateLoader.loadIdentity(from: .pkcs12(data: p12Data, password: password)) {
case .success:
    try store.save(p12Data)
case .renewalRequired, .unavailable:
    throw EnrolmentError.invalidBundle
}
```

**Important:** The keychain source uses the data protection keychain. On macOS this means unsigned test bundles cannot read it and the result is `.unavailable`. That is expected, see <doc:Troubleshooting>.
