# ``PinGuard/Pin``

## Overview

A pin is one expected hash. The ``type`` says what was hashed, the ``hash`` is the Base64 SHA-256 digest, the ``role`` tells a primary pin from its backup and the ``scope`` limits where in the chain it may match. Only the first two are required:

```swift
Pin(type: .spki, hash: "PRIMARY_PIN_BASE64=")
Pin(type: .spki, hash: "BACKUP_PIN_BASE64=", role: .backup)
Pin(type: .ca, hash: "INTERMEDIATE_CERT_HASH=", scope: .intermediate)
```

Pins are `Codable` with the same field names. `role` and `scope` may be left out of JSON and default to `.primary` and `.any`. Use ``PinHasher`` to compute the hash from a `SecKey` or `SecCertificate` at runtime, or the `openssl` command in <doc:GettingStarted> from a terminal.

## Topics

### Creating a pin

- ``init(type:hash:role:scope:)``

### Fields

- ``type``
- ``hash``
- ``role``
- ``scope``

### Encoding and decoding

- ``init(from:)``
- ``encode(to:)``
