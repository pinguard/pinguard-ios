# ``PinGuard/PublicKeyRemoteConfigVerifier``

## Overview

This verifier checks an ECDSA signature made with a P-256 key over the SHA-256 of the payload. The closure returns the X9.63 representation of the public key for the identifier in the blob, which is the 65 byte uncompressed point `04 || X || Y`:

```swift
let verifier = PublicKeyRemoteConfigVerifier { keyID in
    RemoteConfigKeys.publicKey(for: keyID)
}
```

Both signature encodings are accepted: the raw 64 byte `r || s` form and the DER form that `openssl` and most server libraries produce. The verifier returns `false` for another scheme, an unknown key identifier or a malformed key.

Because only the public key lives in the app, a leaked binary does not let anyone sign configuration. This is the verifier to prefer when more than one party consumes the same remote configuration.

## Topics

### Creating a verifier

- ``init(publicKeyProvider:)``

### Verifying

- ``verify(blob:)``
