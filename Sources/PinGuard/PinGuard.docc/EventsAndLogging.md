# Events and Logging

Follow every step PinGuard takes, in Console.app or in your own analytics.

## Overview

PinGuard emits a ``PinGuardEvent`` for everything it does: which policy it found, what the system said about the chain, which pin matched, why a connection was cancelled. By default the events go to the unified log. You can add your own ``PinGuardEventSink`` to forward them anywhere.

## Reading the default log

``OSLogEventSink`` is installed unless you turn it off. It writes under the subsystem `PinGuard` and the category `core`, with a log level that matches the meaning of the event. In Console.app, filter on the subsystem and you will see lines like these:

```
[PinGuard] System trust evaluated: true for api.example.com
[PinGuard] Chain summary for api.example.com CN=*.example.com issuer=*.digicert.com sanCount=2
[PinGuard] Pin matched for api.example.com pins=1
```

All values are marked public so they survive in release builds. There is nothing in them that identifies a user.

## Adding your own sink

For a quick integration, pass a closure to ``PinGuardBuilder/telemetry(_:)``:

```swift
await PinGuard.configure { builder in
    builder.environment(.prod, policySet: policySet)
    builder.telemetry { event in
        switch event {
        case .pinMismatch(let host):
            Analytics.track("pin_mismatch", host: host)
        case .systemTrustFailed(let host, let error):
            Analytics.track("system_trust_failed", host: host, error: error)
        default:
            break
        }
    }
    builder.systemLogging(false)
}
```

For anything bigger than a closure, conform a type to ``PinGuardEventSink`` and register it with ``PinGuardBuilder/addEventSink(_:)``. Several sinks can coexist, and each one receives every event.

**Important:** Sinks are called synchronously on the thread that evaluates the challenge, which is a `URLSession` delegate thread. Keep the work short and hop to the main actor yourself before touching UI.

## The events

| Event | When |
|---|---|
| `policyMissing` | No policy matched the host and there was no default |
| `systemTrustEvaluated` | The operating system finished its own check; carries the result |
| `systemTrustFailed` | The system rejected the chain and the policy is strict |
| `systemTrustFailedPermissive` | The system rejected the chain but the policy is permissive |
| `chainSummary` | Redacted leaf name, issuer name and SAN count of the chain |
| `pinMatched` | At least one pin matched; carries the matching pins |
| `pinMismatch` | No pin matched and the connection was cancelled |
| `pinMismatchAllowedByFallback` | No pin matched but `allowSystemTrustFallback` let it through |
| `pinMismatchPermissive` | No pin matched but the policy is permissive |
| `pinSetEmpty` | The matched policy has no pins |
| `mtlsIdentityUsed` | A client certificate was presented |
| `mtlsIdentityMissing` | The server asked for a client certificate and none was available |
| `remoteConfigApplied` | A signed remote configuration replaced a policy set |
| `remoteConfigRejected` | A remote configuration failed verification or decoding |

A normal pinned request produces three events in order: `systemTrustEvaluated`, `chainSummary` and `pinMatched`. The same events are also returned in ``TrustDecision/events``, so you can inspect them without a sink when you call PinGuard directly.

## What a chain summary contains

``ChainSummary`` is deliberately vague. The leaf and issuer subjects are reduced to the last two labels with a wildcard in front, `*.example.com`, and only the number of Subject Alternative Names is reported. Hostnames in events are the ones your app connected to, which you already know. This keeps logs safe to ship to a third party.

## Events in tests

Because sinks are just values, a test can record events in an array and assert on them. The pattern we use in PinGuard's own tests is a small `final class` with a lock around an array, conforming to ``PinGuardEventSink``, injected through ``PinGuardBuilder/addEventSink(_:)``. Pair it with your own ``PinGuard/PinGuard`` instance instead of the shared one so tests stay independent.
