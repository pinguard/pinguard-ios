# ``PinGuard/PinGuard``

## Overview

`PinGuard` is an actor. It owns one ``PinGuardConfiguration`` and hands out trust decisions based on it. Most apps use the shared instance and configure it once at launch:

```swift
await PinGuard.configure { builder in
    builder.environment(.prod, policySet: policySet)
    builder.selectEnvironment(.prod)
}
```

Every other entry point in the SDK, ``PinGuardSession`` and ``PinGuardURLSessionDelegate`` included, defaults to ``shared`` and accepts your own instance instead. Create one with ``init(configuration:)`` when you want to keep the configuration out of global state, for example in tests.

Evaluation is `nonisolated`. ``evaluate(serverTrust:host:)`` reads a snapshot of the configuration, then runs system trust and pin matching outside the actor, so a slow TLS evaluation never blocks a configuration update and the `SecTrust` never crosses an isolation boundary.

## Topics

### The shared instance

- ``shared``
- ``configure(_:)-swift.type.method``

### Creating an instance

- ``init(configuration:)``

### Reading and changing the configuration

- ``currentConfiguration``
- ``configure(_:)-swift.method``
- ``update(configuration:)``
- ``apply(remoteConfig:verifier:to:)``

### Evaluating a connection

- ``evaluate(serverTrust:host:)``
