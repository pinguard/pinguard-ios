# ``PinGuard/HostPattern``

## Overview

A pattern selects hosts. `.exact` matches one hostname, `.wildcard` matches hosts with exactly one extra label in front of the suffix:

```swift
HostPattern.exact("api.example.com")   // api.example.com only
HostPattern.wildcard("example.com")    // api.example.com, www.example.com, not example.com
HostPattern.parse("*.example.com")     // same as .wildcard("example.com")
```

Matching is case insensitive and ignores leading and trailing dots. The string form, `*.example.com` for a wildcard, is what ``parse(_:)`` reads and ``rawValue`` writes. It is also how a pattern is encoded in JSON, which keeps remote configuration payloads short.

## Topics

### Patterns

- ``exact(_:)``
- ``wildcard(_:)``

### String form

- ``parse(_:)``
- ``rawValue``

### Encoding and decoding

- ``init(from:)``
- ``encode(to:)``
