# Getting Started

Add PinGuard to your app, compute your first pins and make a pinned request.

## Overview

In this article we add the package, pin one API host with a primary and a backup key, and run a request through a pinned session. It takes about ten minutes if you have access to a terminal and your server.

## Requirements

PinGuard is a Swift package with no third party dependencies. It links only `Foundation`, `Security`, `CryptoKit` and `os`.

| | Minimum |
|---|---|
| Xcode | 26 |
| Swift | 6.2, the package uses Swift 6 language mode |
| iOS | 15 |
| macOS | 12 |
| tvOS | 15 |
| watchOS | 8 |
| visionOS | 1 |

## Step 1: Adding the package

In Xcode, choose File, then Add Package Dependencies, and paste the repository URL. If you manage dependencies in a `Package.swift`, add it there instead:

```swift
dependencies: [
    .package(url: "https://github.com/pinguard/pinguard-ios.git", from: "1.0.2")
]
```

Then add `PinGuard` to the dependencies of the target that makes network requests.

## Step 2: Computing the pins

A pin is the Base64 encoded SHA-256 hash of something in the server's certificate chain. We recommend pinning the Subject Public Key Info, SPKI for short, because the public key usually survives certificate renewals. This command prints the SPKI pin of a live server:

```bash
openssl s_client -connect api.example.com:443 -servername api.example.com </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | base64
```

Run it once for the key your server uses today and once for the key you will rotate to. You need both.

**Important:** Always ship at least two pins. If the only pinned key is replaced and you have no backup, every user is locked out until they update the app.

If you would rather compute pins inside the app, for example in an internal tool, ``PinHasher`` does the same work on a `SecKey` or a `SecCertificate`.

## Step 3: Configuring PinGuard at launch

PinGuard keeps its configuration in a shared actor. We configure it once, before the first request. The configuration is a set of ``HostPolicy`` values, each binding a ``HostPattern`` to a ``PinningPolicy``:

```swift
import PinGuard

enum PinGuardSetup {

    static func configure() async {
        let policy = PinningPolicy(pins: [
            Pin(type: .spki, hash: "PRIMARY_PIN_BASE64=", role: .primary),
            Pin(type: .spki, hash: "BACKUP_PIN_BASE64=", role: .backup)
        ])

        let policySet = PolicySet(policies: [
            HostPolicy(pattern: .exact("api.example.com"), policy: policy),
            HostPolicy(pattern: .wildcard("example.com"), policy: policy)
        ])

        await PinGuard.configure { builder in
            builder.environment(.prod, policySet: policySet)
            builder.selectEnvironment(.prod)
        }
    }
}
```

``PinGuard/PinGuard/configure(_:)-swift.type.method`` is `async` because ``PinGuard/PinGuard/shared`` is an actor. In a SwiftUI app the natural place to call it is a `.task` on the root view:

```swift
@main
struct MyApp: App {

    var body: some Scene {
        WindowGroup {
            ContentView()
                .task {
                    await PinGuardSetup.configure()
                }
        }
    }
}
```

In a UIKit app, start a `Task` in `application(_:didFinishLaunchingWithOptions:)` and await the same call.

If you prefer to avoid shared state, build the configuration synchronously and keep your own instance:

```swift
var builder = PinGuardBuilder()
builder.environment(.prod, policySet: policySet)
let pinGuard = PinGuard(configuration: builder.build())
```

Every entry point that defaults to the shared instance also accepts a `pinGuard:` argument, so injecting your own instance costs nothing.

## Step 4: Making a pinned request

``PinGuardSession`` wraps a `URLSession` whose delegate runs PinGuard on every server trust challenge:

```swift
let session = PinGuardSession()
let url = URL(string: "https://api.example.com/v1/profile")!
let (data, response) = try await session.data(from: url)
```

If you already own a `URLSession`, keep it and attach ``PinGuardURLSessionDelegate`` instead:

```swift
let delegate = PinGuardURLSessionDelegate()
let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
```

Note that a `URLSession` retains its delegate until you invalidate the session. ``PinGuardSession`` takes care of that in its `deinit`; with your own session you call `finishTasksAndInvalidate()` yourself.

## What happens on each request

The result is a ``TrustDecision``. When the pin matches, the connection proceeds and you see a `pinMatched` event in Console.app under the `PinGuard` subsystem. When nothing matches, PinGuard cancels the challenge, `URLSession` fails the task with a cancelled authentication error, and you see `pinMismatch`.

That is the whole integration. The rest of the documentation covers the optional parts: <doc:PinsAndPolicies> for the switches on a policy, <doc:HostMatching> for how a host finds its policy, <doc:Environments> for dev and production sets, <doc:EventsAndLogging> for telemetry, <doc:MutualTLS> for client certificates and <doc:RemoteConfiguration> for updating pins without a release.
