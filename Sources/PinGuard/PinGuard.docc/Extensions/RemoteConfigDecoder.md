# ``PinGuard/RemoteConfigDecoder``

## Overview

The decoder verifies a ``RemoteConfigBlob`` and returns the ``PolicySet`` inside it, in that order. The signature is checked before a single byte of JSON is parsed:

```swift
let decoder = RemoteConfigDecoder(verifier: HMACRemoteConfigVerifier { secretID in
    Keychain.secret(for: secretID)
})
let policySet = try decoder.decode(blob)
```

``PinGuard/PinGuard/apply(remoteConfig:verifier:to:)`` uses the decoder internally and then swaps the policy set. Use the decoder directly when you want the policy set without applying it, for example to store it or to show the pins it contains in an internal tool.

## Topics

### Creating a decoder

- ``init(verifier:)``

### Decoding

- ``decode(_:)``
