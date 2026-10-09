# ``PinGuard/PinGuardEnvironment``

## Overview

An environment is just a name. Three are predefined, and because the type is expressible by a string literal you can introduce your own anywhere a `PinGuardEnvironment` is expected:

```swift
builder.environment(.prod, policySet: prodPolicies)
builder.environment("staging", policySet: stagingPolicies)
builder.selectEnvironment("staging")
```

The name appears in `remoteConfigApplied` and `remoteConfigRejected` events, so keep it readable.

## Topics

### Predefined environments

- ``dev``
- ``uat``
- ``prod``

### Creating an environment

- ``init(_:)``
- ``init(stringLiteral:)``
- ``name``
