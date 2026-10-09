# ``PinGuard/PinGuardEvent``

## Overview

Events are the audit trail of a trust decision. Every step PinGuard takes emits one, and they arrive at your sinks in the order they happened. A normal pinned request produces `systemTrustEvaluated`, `chainSummary` and `pinMatched`; a cancelled one ends in `pinMismatch`, `systemTrustFailed` or `policyMissing`.

Hosts in events are the ones your app connected to. Certificate names inside ``ChainSummary`` are redacted, so an event never carries anything that identifies a user. See <doc:EventsAndLogging> for the full table and for how to receive events.

## Topics

### Policy lookup

- ``policyMissing(host:)``

### System trust

- ``systemTrustEvaluated(host:isTrusted:)``
- ``systemTrustFailed(host:error:)``
- ``systemTrustFailedPermissive(host:)``

### Pin matching

- ``chainSummary(host:summary:)``
- ``pinMatched(host:pins:)``
- ``pinMismatch(host:)``
- ``pinMismatchAllowedByFallback(host:)``
- ``pinMismatchPermissive(host:)``
- ``pinSetEmpty(host:)``

### Mutual TLS

- ``mtlsIdentityUsed(host:)``
- ``mtlsIdentityMissing(host:)``

### Remote configuration

- ``remoteConfigApplied(environment:)``
- ``remoteConfigRejected(environment:error:)``
