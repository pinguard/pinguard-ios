# ``PinGuard/TrustEvaluator``

## Overview

The evaluator is the engine behind ``PinGuard/PinGuard``. It takes one ``PolicySet`` and optional sinks, and it evaluates a `SecTrust` for a host without touching any shared state:

```swift
let evaluator = TrustEvaluator(policySet: policySet)
let decision = await evaluator.evaluate(serverTrust: trust, host: "api.example.com")
```

Use it directly when the configuration is static and you don't need environments, or in tests where you want full control over the policy set. The decision logic is the same one described in <doc:SecurityModel>, and the result is a ``TrustDecision``.

## Topics

### Creating an evaluator

- ``init(policySet:eventSinks:)``

### Evaluating a connection

- ``evaluate(serverTrust:host:)``
