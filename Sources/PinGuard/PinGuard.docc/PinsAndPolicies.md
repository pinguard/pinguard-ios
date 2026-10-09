# Pins and Policies

Describe which hashes a server must present and how strictly PinGuard enforces them.

## Overview

A ``PinningPolicy`` is a list of ``Pin`` values plus three switches. The pins say what the chain must contain, the switches say what happens when it doesn't. We go through both, then look at the combinations that make sense in practice.

## Anatomy of a pin

Each pin has four fields. Only the first two are required:

```swift
Pin(type: .spki, hash: "PRIMARY_PIN_BASE64=", role: .primary, scope: .any)
```

| Field | Values | Meaning |
|---|---|---|
| `type` | `.spki`, `.certificate`, `.ca` | Hash of the public key, of the whole certificate, or of a CA certificate in the chain |
| `hash` | Base64 string | The SHA-256 digest to compare against |
| `role` | `.primary`, `.backup` | Informational. Both are accepted. It tells you which one matched in a `pinMatched` event |
| `scope` | `.any`, `.leaf`, `.intermediate`, `.root` | Which position in the chain the pin may match |

### Choosing a pin type

`.spki` hashes the Subject Public Key Info, so it stays valid as long as the key stays the same. Most certificate renewals keep the key, which makes SPKI pins the ones that break least often. Pin the public key unless you have a reason not to.

`.certificate` hashes the DER bytes of the whole certificate. Every renewal changes it, so you will be shipping new pins every year or sooner. It is useful when you must bind to one exact certificate.

`.ca` also hashes a whole certificate, but it only matches intermediate and root certificates. Use it when you trust one authority to issue for your domain and you want freedom at the leaf. It is weaker than a leaf pin because that authority can issue any certificate it likes.

### Choosing a scope

The chain PinGuard inspects is the one the operating system built, so it normally includes the root even when the server does not send it. The first certificate is the leaf, the last is the root, everything between is an intermediate. A chain with a single certificate counts as a leaf.

`.any` lets the pin match wherever it appears. `.leaf`, `.intermediate` and `.root` restrict it to one position. A `.ca` pin with `.leaf` scope can never match, which is on purpose.

## The three switches

```swift
PinningPolicy(
    pins: [primary, backup],
    failStrategy: .strict,
    requireSystemTrust: true,
    allowSystemTrustFallback: false
)
```

These are the defaults. Keep them in production.

`requireSystemTrust` decides whether the operating system has to accept the chain before pins are compared. When it is `true` and the system rejects the chain, PinGuard stops right there. When it is `false`, pins are compared anyway and a match is enough to trust the connection. Turning it off makes sense only for a private test server with a self signed certificate.

`failStrategy` picks between `.strict` and `.permissive`. A `.permissive` policy reports failures through events but lets the connection through, both when the system rejects the chain and when no pin matches. Note that a permissive pin mismatch is only accepted if the system trusted the chain; a mismatch on an untrusted chain is still cancelled.

`allowSystemTrustFallback` accepts a pin mismatch when the system trusted the chain. It is narrower than `.permissive` because it never rescues a system trust failure.

## Combinations that occur in practice

A rollout usually goes through three stages. First you ship with `.permissive` and watch the events for `pinMismatchPermissive`. Nothing breaks for users, and you learn whether your pins are right. Then you switch to `.strict` with `allowSystemTrustFallback: true`, which still lets a renewal you missed go through while telling you about it. Finally you remove the fallback.

| Stage | failStrategy | allowSystemTrustFallback | Mismatch outcome |
|---|---|---|---|
| Observe | `.permissive` | `false` | Logged as `pinMismatchPermissive`, connection proceeds |
| Soft enforce | `.strict` | `true` | Logged as `pinMismatchAllowedByFallback`, connection proceeds |
| Enforce | `.strict` | `false` | Logged as `pinMismatch`, connection cancelled |

An empty pin list is treated like a mismatch. PinGuard emits `pinSetEmpty` and then applies the same switches.

## Policies are values

``PinningPolicy``, ``Pin`` and the enums around them are `Hashable`, `Codable` and `Sendable`. You can keep them in a JSON file, compare them in tests and send them across actors. The `Codable` form is the same one <doc:RemoteConfiguration> uses, so a policy you write in Swift and one you receive from the backend are interchangeable.
