# ``PinGuard/HMACRemoteConfigVerifier``

## Overview

This verifier checks an HMAC-SHA256 tag over the payload. You give it a closure that returns the shared secret for the identifier carried in the blob, which lets you rotate secrets by introducing a new identifier:

```swift
let verifier = HMACRemoteConfigVerifier { secretID in
    Keychain.secret(for: secretID)
}
```

The comparison is constant time, courtesy of CryptoKit. The verifier returns `false` when the blob was signed with another scheme or when the closure returns `nil`, so an unknown secret identifier is treated as a bad signature rather than an error.

**Important:** Whoever holds the secret can sign configuration. Keep it in the keychain, never in source or in a plist.

## Topics

### Creating a verifier

- ``init(secretProvider:)``

### Verifying

- ``verify(blob:)``
