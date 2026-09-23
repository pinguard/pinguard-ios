# PinGuard Example App

A small SwiftUI app that shows how PinGuard is set up and what it does at runtime. Open it, tap around, and watch the event log.

## Requirements

- Xcode 26 or newer
- iOS 17 or newer (the SDK itself still supports iOS 15, the demo just uses newer SwiftUI)

## Run it

```bash
cd Example
open Example.xcodeproj
```

Pick a simulator and press Run. The project points to the SDK in the parent folder, so nothing needs to be downloaded.

## What you will see

| Screen | What it shows |
|---|---|
| Live request to example.com | A real HTTPS request through `PinGuardSession`. The events it produces show up underneath. |
| Compute a pin from a certificate | Paste a certificate and get its SPKI and certificate pins. This is how you produce the values you put in your policy. |
| Which policy matches a host? | Type a host and see which exact or wildcard pattern matches it. |
| Apply a signed remote config | Sign a JSON payload with HMAC and apply it. Flip the toggle to break the signature and watch PinGuard reject it. |
| Event log | Everything PinGuard emitted since launch. |

## Where to look in the code

- `PinGuardSetup.swift` is the only place that talks to PinGuard's configuration. Start there.
- `ExampleApp.swift` calls that setup once, inside `.task`, because configuring the shared `PinGuard` is an `await`.
- `EventLogSink.swift` is a tiny `PinGuardEventSink` that pushes events to the UI. Your app would send them to your analytics instead.

## A note on the demo pins

The primary pin belongs to the certificate example.com was serving when this demo was written. Certificates rotate, so the demo policy has `allowSystemTrustFallback: true`. That means a mismatch is logged but the request still goes through as long as the system trusts the chain. Do not ship that setting to production. Use `.strict` with a primary and a backup pin instead.
