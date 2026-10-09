# ``PinGuard/PinGuardConfiguration``

## Overview

A configuration is a plain value with three parts: the registered environments, the name of the current one and the sinks that receive events. ``PinGuardBuilder`` produces one, ``PinGuard/PinGuard`` stores one, and you can read, copy and modify it like any struct:

```swift
var configuration = await PinGuard.shared.currentConfiguration
configuration.current = .dev
await PinGuard.shared.update(configuration: configuration)
```

The two computed properties resolve the current environment for you. ``activePolicySet`` returns an empty ``PolicySet`` when the current environment is not registered, which makes every host fail with `policyMissing` rather than crashing.

## Topics

### Stored state

- ``environments``
- ``current``
- ``eventSinks``

### Resolving the current environment

- ``activePolicySet``
- ``activeMTLS``
