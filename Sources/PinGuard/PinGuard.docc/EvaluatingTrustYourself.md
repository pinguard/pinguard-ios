# Evaluating Trust Yourself

Ask PinGuard for a decision when you are not using `URLSession`, or when you want to see the reasoning.

## Overview

``PinGuardSession`` and ``PinGuardURLSessionDelegate`` cover the common case. Sometimes you hold a `SecTrust` from somewhere else, a `Network.framework` connection or a `WKWebView` navigation delegate for example, and you still want the same decision. Two entry points give you that.

## Through the actor

``PinGuard/PinGuard/evaluate(serverTrust:host:)`` uses the active configuration and the registered sinks:

```swift
let decision = await PinGuard.shared.evaluate(serverTrust: trust, host: "api.example.com")
if decision.isTrusted {
    // Proceed. decision.reason says why.
} else {
    // Cancel. decision.events says what happened.
}
```

The method is `nonisolated` and `async`. It takes a snapshot of the configuration, so a concurrent ``PinGuard/PinGuard/update(configuration:)`` cannot change the rules halfway through one evaluation. The `SecTrust` stays in your isolation region; it is never sent across actors.

## Standalone

``TrustEvaluator`` runs the same logic for one ``PolicySet`` without a ``PinGuard/PinGuard`` instance. It is handy in tests and in tools that check a server before you ship its pins:

```swift
let evaluator = TrustEvaluator(policySet: policySet, eventSinks: [RecordingSink()])
let decision = await evaluator.evaluate(serverTrust: trust, host: "api.example.com")
```

Event sinks default to none, so a standalone evaluator is silent unless you ask otherwise.

## Reading the decision

A ``TrustDecision`` has three fields.

`isTrusted` is the only one the delegate looks at.

`reason` is a ``TrustDecisionReason`` that names the single rule that settled the outcome:

| Reason | isTrusted | Meaning |
|---|---|---|
| `pinMatch` | `true` | At least one pin matched |
| `systemTrustFailedPermissive` | `true` | The system rejected the chain but the policy is permissive |
| `pinMismatchAllowedByFallback` | `true` | No pin matched, the system trusted the chain and `allowSystemTrustFallback` is on |
| `pinMismatchPermissive` | `true` | No pin matched, the system trusted the chain and the policy is permissive |
| `trustFailed` | `false` | The system rejected the chain and the policy is strict |
| `policyMissing` | `false` | No policy matched the host |
| `pinningFailed` | `false` | No pin matched and nothing allowed it through |

`events` lists every ``PinGuardEvent`` emitted during this evaluation, in order. They are the same events your sinks received, which makes the decision self describing in a log or a bug report.

## Where the hostname comes from

Pass the host you intended to reach, the one you would put in the URL. PinGuard normalizes it, selects the policy with it and also hands it to the system SSL policy, so a certificate for a different name fails system trust the way it should. Passing an IP address or an empty string leads to `policyMissing` unless you wrote a policy for that value.

## Computing pins at runtime

``PinHasher`` exposes the two hash functions PinGuard uses internally:

```swift
let spkiPin = try PinHasher.spkiHash(for: publicKey)
let certificatePin = PinHasher.certificateHash(for: certificate)
```

``PinHasher/spkiHash(for:)`` supports RSA keys and EC keys on the P-256, P-384 and P-521 curves, which covers every key a public authority issues today. Any other key type throws ``PinGuardError/unsupportedKeyType``. A certificate with such a key can still be pinned with a `.certificate` pin, and an `.spki` pin can never match it.
