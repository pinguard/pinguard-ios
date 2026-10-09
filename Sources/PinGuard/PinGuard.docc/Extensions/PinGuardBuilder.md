# ``PinGuard/PinGuardBuilder``

## Overview

The builder is the friendly way to produce a ``PinGuardConfiguration``. You add environments, pick the active one, attach sinks and call ``build()``. The closure form of ``PinGuard/PinGuard/configure(_:)-swift.type.method`` does the building for you:

```swift
await PinGuard.configure { builder in
    builder.environment(.dev, policySet: devPolicies)
    builder.environment(.prod, policySet: prodPolicies, mtls: prodMTLS)
    builder.selectEnvironment(.prod)
    builder.telemetry { event in
        print(event)
    }
}
```

The defaults are sensible for production: the current environment is `.prod` and ``OSLogEventSink`` is installed unless you call ``systemLogging(_:)`` with `false`. Sinks you add are appended after the system logger, so the order in which they receive events is the order in which you registered them.

## Topics

### Environments

- ``environment(_:policySet:mtls:)``
- ``selectEnvironment(_:)``

### Events

- ``addEventSink(_:)``
- ``telemetry(_:)``
- ``systemLogging(_:)``

### Producing the configuration

- ``build()``
