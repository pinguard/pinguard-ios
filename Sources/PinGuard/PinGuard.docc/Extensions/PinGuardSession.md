# ``PinGuard/PinGuardSession``

## Overview

`PinGuardSession` is the shortest path to a pinned request. It creates a `URLSession` with a ``PinGuardURLSessionDelegate`` and exposes the two async data methods most apps need:

```swift
let session = PinGuardSession()
let (data, response) = try await session.data(from: url)
```

Pass a `URLSessionConfiguration` to tune caching, timeouts or headers, and a `pinGuard:` instance when you don't use the shared one. The session is invalidated in `deinit` with `finishTasksAndInvalidate()`, so the delegate is released when you let go of the wrapper.

If you need upload, download or background tasks, create your own `URLSession` with ``PinGuardURLSessionDelegate`` instead. The pinning behaviour is identical.

## Topics

### Creating a session

- ``init(configuration:pinGuard:)``

### Making requests

- ``data(for:)``
- ``data(from:)``
