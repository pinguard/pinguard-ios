# ``PinGuard/PinHasher``

## Overview

`PinHasher` produces the Base64 SHA-256 digests that pins are compared against, using the same code path PinGuard uses during evaluation:

```swift
let spkiPin = try PinHasher.spkiHash(for: publicKey)
let certificatePin = PinHasher.certificateHash(for: certificate)
```

``spkiHash(for:)`` rebuilds the DER SubjectPublicKeyInfo from the key's external representation, so the result equals what the `openssl` pipeline in <doc:GettingStarted> prints. RSA keys and EC keys on P-256, P-384 and P-521 are supported. Any other key throws ``PinGuardError/unsupportedKeyType``.

``certificateHash(for:)`` hashes the certificate's DER bytes and cannot fail.

## Topics

### Computing hashes

- ``spkiHash(for:)``
- ``certificateHash(for:)``
