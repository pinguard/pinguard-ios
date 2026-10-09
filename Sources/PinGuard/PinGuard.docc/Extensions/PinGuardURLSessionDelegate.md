# ``PinGuard/PinGuardURLSessionDelegate``

## Overview

Attach this delegate to any `URLSession` and PinGuard handles its authentication challenges:

```swift
let delegate = PinGuardURLSessionDelegate()
let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
```

Server trust challenges go through ``PinGuard/PinGuard/evaluate(serverTrust:host:)``. A trusted decision answers with `.useCredential` and the server's trust object, anything else cancels the challenge. Client certificate challenges are answered from the ``MTLSConfiguration`` of the active environment, see <doc:MutualTLS>. Every other authentication method falls back to default handling, so HTTP basic or NTLM prompts behave as they would without PinGuard.

Both the session level and the task level challenge methods are implemented, which means the delegate works whether `URLSession` routes the challenge to the session or to a task.

Note that `URLSession` retains its delegate until the session is invalidated. Call `finishTasksAndInvalidate()` when you are done with the session, or use ``PinGuardSession`` which does it for you.

## Topics

### Creating a delegate

- ``init(pinGuard:)``

### Handling challenges

- ``urlSession(_:didReceive:)``
- ``urlSession(_:task:didReceive:)``
