# ``PinGuard``

Certificate pinning for `URLSession`, written in Swift 6 with structured concurrency.

## Overview

When your app opens an HTTPS connection, the operating system already checks that the server's certificate is valid and signed by a trusted authority. PinGuard adds one more check on top of that: the certificate, or more often its public key, must match a hash you shipped with the app. If a network attacker somehow presents a valid certificate for your domain, the hash will not match and PinGuard cancels the connection.

The whole integration is three steps. You compute the pins for your servers, you describe them in a ``PolicySet``, and you hand that policy set to PinGuard once at launch:

```swift
import PinGuard

await PinGuard.configure { builder in
    builder.environment(.prod, policySet: policySet)
    builder.selectEnvironment(.prod)
}

let session = PinGuardSession()
let (data, response) = try await session.data(from: url)
```

From then on every server trust challenge goes through PinGuard. You get a ``TrustDecision`` for each connection and a stream of ``PinGuardEvent`` values you can log or send to analytics.

Everything else is optional. You can register several environments and switch between them, present a client certificate for mutual TLS, and update pins without an app release through signed remote configuration. Start with <doc:GettingStarted>, then read <doc:SecurityModel> so you know exactly what pinning does and does not protect you from.

## Topics

### Essentials

- <doc:GettingStarted>
- <doc:SecurityModel>
- ``PinGuard/PinGuard``
- ``PinGuardSession``
- ``PinGuardURLSessionDelegate``

### Configuration

- <doc:Environments>
- ``PinGuardBuilder``
- ``PinGuardConfiguration``
- ``PinGuardEnvironment``
- ``PinGuardEnvironmentConfiguration``

### Pins and policies

- <doc:PinsAndPolicies>
- <doc:HostMatching>
- ``PolicySet``
- ``HostPolicy``
- ``HostPattern``
- ``HostMatcher``
- ``PinningPolicy``
- ``Pin``
- ``PinType``
- ``PinRole``
- ``PinScope``
- ``FailStrategy``

### Trust decisions

- <doc:EvaluatingTrustYourself>
- ``TrustEvaluator``
- ``TrustDecision``
- ``TrustDecisionReason``
- ``ChainSummary``
- ``PinHasher``

### Events and logging

- <doc:EventsAndLogging>
- ``PinGuardEvent``
- ``PinGuardEventSink``
- ``ClosureEventSink``
- ``OSLogEventSink``

### Mutual TLS

- <doc:MutualTLS>
- ``MTLSConfiguration``
- ``ClientCertificateProvider``
- ``StaticClientCertificateProvider``
- ``ClientCertificateSource``
- ``ClientCertificateLoader``
- ``ClientIdentityResult``

### Remote configuration

- <doc:RemoteConfiguration>
- ``RemoteConfigBlob``
- ``RemoteConfigSignature``
- ``RemoteConfigPayload``
- ``RemoteConfigDecoder``
- ``RemoteConfigVerifier``
- ``HMACRemoteConfigVerifier``
- ``PublicKeyRemoteConfigVerifier``
- ``RemoteConfigThreatModel``

### Errors

- ``PinGuardError``

### Diagnosing problems

- <doc:Troubleshooting>
