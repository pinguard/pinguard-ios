# ``PinGuard/TrustDecision``

## Overview

A decision is what ``PinGuard/PinGuard/evaluate(serverTrust:host:)`` and ``TrustEvaluator/evaluate(serverTrust:host:)`` return. ``isTrusted`` is the verdict, ``reason`` is the single rule that produced it and ``events`` is everything that happened along the way:

```swift
let decision = await PinGuard.shared.evaluate(serverTrust: trust, host: host)
guard decision.isTrusted else {
    logger.error("Rejected \(host): \(String(describing: decision.reason))")
    return
}
```

Because the events are included, a decision explains itself without a sink. <doc:EvaluatingTrustYourself> lists every reason and the verdict it implies.

## Topics

### Creating a decision

- ``init(isTrusted:reason:events:)``

### Reading the outcome

- ``isTrusted``
- ``reason``
- ``events``
