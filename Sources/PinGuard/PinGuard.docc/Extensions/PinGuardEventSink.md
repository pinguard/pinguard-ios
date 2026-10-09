# ``PinGuard/PinGuardEventSink``

## Overview

A sink receives every ``PinGuardEvent``. The SDK ships two: ``OSLogEventSink`` writes to the unified log and ``ClosureEventSink`` calls a closure. Conform to the protocol yourself when you want to batch events, count them or forward them to an analytics client:

```swift
struct AnalyticsSink: PinGuardEventSink {

    let client: AnalyticsClient

    func receive(_ event: PinGuardEvent) {
        switch event {
        case .pinMismatch(let host):
            client.track("pin_mismatch", properties: ["host": host])
        default:
            break
        }
    }
}
```

Register it with ``PinGuardBuilder/addEventSink(_:)``. Sinks must be `Sendable` because they are stored in the configuration and called from `URLSession` delegate threads. ``receive(_:)`` is synchronous and runs on the thread that evaluates the challenge, so keep it quick and move UI work to the main actor yourself.

## Topics

### Receiving events

- ``receive(_:)``
