# ``PinGuard/PolicySet``

## Overview

A policy set is everything one environment knows about its hosts: a list of ``HostPolicy`` values and an optional ``defaultPolicy`` for hosts none of them match.

```swift
let policySet = PolicySet(policies: [
    HostPolicy(pattern: .exact("api.example.com"), policy: apiPolicy),
    HostPolicy(pattern: .wildcard("example.com"), policy: webPolicy)
])
```

The order of the list does not matter. PinGuard picks an exact match first, then the wildcard with the longest suffix, then the default. Without a default, unknown hosts are rejected with `policyMissing`. <doc:HostMatching> has the full rules.

## Topics

### Creating a policy set

- ``init(policies:defaultPolicy:)``

### Contents

- ``policies``
- ``defaultPolicy``
