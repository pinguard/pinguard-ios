# ``PinGuard/PinningPolicy``

## Overview

A policy says which pins a host must present and how strictly a failure is treated. The defaults are the strict ones, and they are what you want in production:

```swift
let policy = PinningPolicy(pins: [
    Pin(type: .spki, hash: "PRIMARY_PIN_BASE64=", role: .primary),
    Pin(type: .spki, hash: "BACKUP_PIN_BASE64=", role: .backup)
])
```

The three switches, ``failStrategy``, ``requireSystemTrust`` and ``allowSystemTrustFallback``, exist for gradual rollouts and for private test servers. <doc:PinsAndPolicies> explains each one and the combinations that make sense.

Policies are `Codable`. Missing keys fall back to the defaults, so a JSON document only needs `pins`. This is the format <doc:RemoteConfiguration> uses.

## Topics

### Creating a policy

- ``init(pins:failStrategy:requireSystemTrust:allowSystemTrustFallback:)``

### Pins

- ``pins``

### Enforcement switches

- ``failStrategy``
- ``requireSystemTrust``
- ``allowSystemTrustFallback``

### Encoding and decoding

- ``init(from:)``
- ``encode(to:)``
