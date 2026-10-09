# ``PinGuard/RemoteConfigBlob``

## Overview

A blob is the unit the backend sends: the JSON payload as bytes, the signature over those bytes and the ``RemoteConfigSignature`` that says how to check it.

```swift
let blob = RemoteConfigBlob(
    payload: payloadData,
    signature: signatureData,
    signatureType: .hmacSHA256(secretID: "v1")
)
```

Keep the payload exactly as received. Re serializing the JSON changes the bytes and the signature stops matching. The blob itself is `Codable`, so you can also receive it as one JSON object with the payload and signature Base64 encoded. See <doc:RemoteConfiguration>.

## Topics

### Creating a blob

- ``init(payload:signature:signatureType:)``

### Contents

- ``payload``
- ``signature``
- ``signatureType``
