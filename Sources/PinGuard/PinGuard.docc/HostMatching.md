# Host Matching

How a hostname finds its policy, and what happens when several patterns match.

## Overview

A ``PolicySet`` holds a list of ``HostPolicy`` values and an optional default. Each host policy pairs a ``HostPattern`` with a ``PinningPolicy``. On every challenge PinGuard takes the host from the protection space, normalizes it and picks exactly one policy. This article explains the rules.

## Exact and wildcard patterns

There are two kinds of pattern:

```swift
HostPolicy(pattern: .exact("api.example.com"), policy: apiPolicy)
HostPolicy(pattern: .wildcard("example.com"), policy: defaultPolicy)
```

`.exact` matches one hostname and nothing else.

`.wildcard("example.com")` matches `api.example.com` and `www.example.com`. It does not match `example.com` itself, and it does not match `a.b.example.com`. The wildcard stands for exactly one label, the same way a `*.example.com` certificate does. If you want the base domain covered as well, add an `.exact` entry for it.

You can also write patterns as strings. ``HostPattern/parse(_:)`` turns `"*.example.com"` into a wildcard and anything else into an exact pattern:

```swift
let pattern = HostPattern.parse("*.example.com")
```

This is the form the JSON in <doc:RemoteConfiguration> uses, and ``HostPattern/rawValue`` gives it back.

## Normalization

Before matching, both the host and the pattern are lowercased and leading or trailing dots are removed. `API.Example.com.` and `api.example.com` are the same host. An empty host after normalization never matches anything and produces `policyMissing`.

## Precedence

When more than one pattern matches a host, PinGuard picks in this order:

1. An exact match always wins.
2. Among wildcards, the one with the longest suffix wins. `*.eu.example.com` beats `*.example.com` for `api.eu.example.com`.
3. If nothing matched, the `defaultPolicy` of the set is used.
4. If there is no default either, the result is `policyMissing` and the connection is cancelled.

You can test the rule in isolation with ``HostMatcher/matches(_:host:)``:

```swift
HostMatcher.matches(.wildcard("example.com"), host: "api.example.com") // true
HostMatcher.matches(.wildcard("example.com"), host: "example.com")     // false
```

## Using a default policy

`PolicySet(policies:defaultPolicy:)` takes an optional policy for hosts nothing else matched:

```swift
let policySet = PolicySet(
    policies: [HostPolicy(pattern: .exact("api.example.com"), policy: apiPolicy)],
    defaultPolicy: PinningPolicy(pins: [], failStrategy: .permissive)
)
```

Without a default, PinGuard rejects every host you did not list. That is the safe choice when the session only talks to your own servers. A default with an empty pin list and a `.permissive` strategy lets unknown hosts through while still logging them, which is useful for a session that also loads third party content. Remember that an empty pin set produces `pinSetEmpty` on every request to that host, so expect noise in the logs.

**Important:** A default policy applies to any host, including ones an attacker chooses. Give it pins or keep it permissive on purpose, never both empty and strict.
