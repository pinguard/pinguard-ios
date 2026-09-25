# PinGuard

[![Swift](https://img.shields.io/badge/Swift-6.2-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%2015%20|%20macOS%2012%20|%20tvOS%2015%20|%20watchOS%208%20|%20visionOS%201-blue.svg)](https://developer.apple.com)
[![SPM](https://img.shields.io/badge/SPM-Compatible-brightgreen.svg)](https://swift.org/package-manager)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Certificate pinning for `URLSession`, written in Swift 6 with structured concurrency. Optional mutual TLS and signed remote configuration are included.

## What it does

When your app connects to a server, the system already checks that the certificate is valid and signed by a trusted authority. PinGuard adds one more check: the certificate (or its public key) must match a hash you shipped with the app. If a network attacker somehow gets a valid certificate for your domain, the hash will not match and PinGuard cancels the connection.

What it does not do:

- It is not a networking library. It plugs into `URLSession`, it does not replace it.
- It does not detect jailbreaks or protect against someone patching your binary. If the attacker controls the app, they control the pins.
- It does not protect you if you apply unsigned remote configuration. PinGuard refuses to apply a config without a verifier, so this only happens if you go around it.

## Requirements

| | Minimum |
|---|---|
| Xcode | 26 |
| Swift | 6.2 (the package uses Swift 6 language mode) |
| iOS | 15 |
| macOS | 12 |
| tvOS | 15 |
| watchOS | 8 |
| visionOS | 1 |

No third-party dependencies. Only `Foundation`, `Security`, `CryptoKit` and `os`.

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/pinguard/pinguard-ios.git", from: "1.0.2")
]
```

Then add `PinGuard` to your target's dependencies.

## Quick start

### 1. Get the pin for your server

Run this in a terminal. It prints the Base64 SHA-256 of the server's public key, which is what you pin.

```bash
openssl s_client -connect api.example.com:443 -servername api.example.com </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | base64
```

Do the same for your backup key. You need two pins so you can rotate keys without shipping an app update.

### 2. Configure PinGuard once at launch

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

`PinGuard.configure` is `async` because the shared instance is an actor. In SwiftUI, call it from the root view:

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

In UIKit, call it from a `Task` in `application(_:didFinishLaunchingWithOptions:)`.

If you would rather not use a shared instance, build the configuration synchronously and inject your own:

```swift
var builder = PinGuardBuilder()
builder.environment(.prod, policySet: policySet)
let pinGuard = PinGuard(configuration: builder.build())
```

### 3. Make requests

```swift
let session = PinGuardSession()
let (data, response) = try await session.data(from: URL(string: "https://api.example.com/v1/profile")!)
```

`PinGuardSession` wraps a `URLSession` whose delegate runs PinGuard on every server trust challenge. If you already have your own `URLSession`, use the delegate directly:

```swift
let delegate = PinGuardURLSessionDelegate()
let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
```

Both take an optional `pinGuard:` argument when you use your own instance instead of `.shared`.

That is the whole integration. Everything below is optional.

## Policies

A `PinningPolicy` is a list of pins plus three switches:

```swift
PinningPolicy(
    pins: [primary, backup],
    failStrategy: .strict,          // .permissive lets mismatches through, only for rollouts
    requireSystemTrust: true,       // the OS must trust the chain before pins are checked
    allowSystemTrustFallback: false // true accepts a pin mismatch if the OS trusted the chain
)
```

Keep the defaults in production. The two relaxing options exist so you can roll pinning out gradually while watching the events, then tighten.

Each `Pin` has:

| Field | Values | Meaning |
|---|---|---|
| `type` | `.spki`, `.certificate`, `.ca` | Hash of the public key, of the whole certificate, or of a CA certificate in the chain |
| `role` | `.primary`, `.backup` | Informational. Both are accepted. Use it to know which one matched |
| `scope` | `.any`, `.leaf`, `.intermediate`, `.root` | Which position in the chain the pin may match |

Pin the public key (`.spki`) unless you have a reason not to. Public keys survive certificate renewals, so SPKI pins break less often.

## Host matching

```swift
HostPolicy(pattern: .exact("api.example.com"), policy: apiPolicy)
HostPolicy(pattern: .wildcard("example.com"), policy: defaultPolicy)
```

- `.wildcard("example.com")` matches `api.example.com` and `www.example.com`.
- It does not match `example.com` itself, and it does not match `a.b.example.com`. One label only, on purpose.
- Matching is case-insensitive and ignores leading or trailing dots.
- When several patterns match a host, the exact one wins. Among wildcards, the longest suffix wins.
- `PolicySet(policies:defaultPolicy:)` takes an optional default for hosts nothing else matched. Without it, unknown hosts are rejected with `policyMissing`.

You can also write patterns as strings: `HostPattern.parse("*.example.com")`.

## Environments

Register a policy set per environment and pick one. Switching later is a single `await`.

```swift
await PinGuard.configure { builder in
    builder.environment(.dev, policySet: devPolicies)
    builder.environment(.prod, policySet: prodPolicies)
    builder.selectEnvironment(.prod)
}

var configuration = await PinGuard.shared.currentConfiguration
configuration.current = .dev
await PinGuard.shared.update(configuration: configuration)
```

`.dev`, `.uat` and `.prod` are provided. Any string literal works: `builder.environment("staging", policySet: ...)`.

## Events and logging

PinGuard emits a `PinGuardEvent` for every step it takes. By default they go to the unified log under subsystem `PinGuard`, so you can read them in Console.app.

Send them somewhere else with a sink:

```swift
await PinGuard.configure { builder in
    builder.environment(.prod, policySet: policySet)
    builder.telemetry { event in
        switch event {
        case .pinMismatch(let host):
            Analytics.track("pin_mismatch", host: host)
        case .systemTrustFailed(let host, let error):
            Analytics.track("system_trust_failed", host: host, error: error)
        default:
            break
        }
    }
    builder.systemLogging(false) // optional, stops the OSLog output
}
```

For anything bigger than a closure, conform a type to `PinGuardEventSink` and pass it to `builder.addEventSink(_:)`. Sinks are called synchronously from the networking thread, so hop to the main actor yourself if you update UI.

Hosts in events are the ones you connected to. Certificate names are redacted to `*.example.com` form so the log is safe to ship.

| Event | When |
|---|---|
| `policyMissing` | No policy matched the host |
| `systemTrustEvaluated` | The OS finished its own check |
| `systemTrustFailed` | The OS rejected the chain and the policy is strict |
| `systemTrustFailedPermissive` | The OS rejected the chain but the policy is permissive |
| `chainSummary` | Redacted leaf name, issuer name and SAN count |
| `pinMatched` | At least one pin matched |
| `pinMismatch` | No pin matched and the connection was cancelled |
| `pinMismatchAllowedByFallback` | No pin matched but `allowSystemTrustFallback` let it through |
| `pinMismatchPermissive` | No pin matched but the policy is permissive |
| `pinSetEmpty` | The matched policy has no pins |
| `mtlsIdentityUsed` | A client certificate was presented |
| `mtlsIdentityMissing` | The server asked for a client certificate and none was available |
| `remoteConfigApplied` | A signed remote config replaced a policy set |
| `remoteConfigRejected` | A remote config failed verification or decoding |

## Mutual TLS

If your server asks for a client certificate, give the environment an `MTLSConfiguration`:

```swift
let provider = StaticClientCertificateProvider(
    source: .pkcs12(data: p12Data, password: "p12-password")
)

let mtls = MTLSConfiguration(provider: provider) {
    // called when the identity needs renewal, start your re-enrolment flow here
}

builder.environment(.prod, policySet: policySet, mtls: mtls)
```

`.keychain(identityTag:)` loads the identity from the data protection keychain instead. Write your own `ClientCertificateProvider` when the identity comes from somewhere else; the method is `async`, so fetching it is fine.

The delegate reads the mTLS settings of the active environment on every challenge. Switching environments takes effect immediately, no new session needed.

## Remote configuration

You can update pins without an app release. The backend sends a signed blob, PinGuard verifies the signature, decodes the JSON and swaps the policy set of one environment.

The payload looks like this. Fields with defaults (`role`, `scope`, `failStrategy`, `requireSystemTrust`, `allowSystemTrustFallback`) can be left out.

```json
{
  "version": 1,
  "policySet": {
    "policies": [
      {
        "pattern": "*.example.com",
        "policy": {
          "pins": [
            { "type": "spki", "hash": "NEW_PRIMARY=" },
            { "type": "spki", "hash": "NEW_BACKUP=", "role": "backup" }
          ]
        }
      }
    ]
  }
}
```

Apply it:

```swift
let blob = RemoteConfigBlob(payload: json, signature: signature, signatureType: .hmacSHA256(secretID: "v1"))

let verifier = HMACRemoteConfigVerifier { secretID in
    Keychain.secret(for: secretID)
}

try await PinGuard.shared.apply(remoteConfig: blob, verifier: verifier)
```

Two verifiers ship with the SDK:

- `HMACRemoteConfigVerifier` for HMAC-SHA256 with a shared secret. Keep the secret in the keychain.
- `PublicKeyRemoteConfigVerifier` for ECDSA P-256 over SHA-256. It takes the X9.63 bytes of the public key and accepts both raw and DER signatures. Embed the public key in the app.

`apply` throws `PinGuardError.invalidRemoteConfigSignature`, `.invalidRemoteConfigPayload` or `.unsupportedRemoteConfigVersion` and changes nothing when it fails. Use `RemoteConfigDecoder` directly if you want the `PolicySet` without applying it.

## Checking a trust object yourself

If you are not using `URLSession`, you can still ask PinGuard for a decision:

```swift
let decision = await PinGuard.shared.evaluate(serverTrust: trust, host: "api.example.com")
if decision.isTrusted {
    // decision.reason tells you why, decision.events tells you everything that happened
}
```

## Troubleshooting

**Every request fails with `policyMissing`.** No `HostPolicy` matched the host. Check the exact host in the event, remember that a wildcard does not match its own base domain, or add a `defaultPolicy`.

**`pinMismatch` after a certificate renewal.** Your server's key changed and you had no backup pin for the new one. Ship the new pin, or use remote configuration next time. This is exactly why the backup pin exists.

**`systemTrustFailed` on a test server.** The OS itself does not trust the chain: self-signed certificate, expired, wrong host name, or a leaf valid for more than 398 days. Fix the server; do not switch production to `.permissive` to hide it.

**`swift test` fails on a Mac with `unknownKeychainTagIsUnavailable`.** The keychain test uses the data protection keychain, which unsigned test bundles cannot read. It is expected to return `unavailable`; if it returns an identity, something on the machine is granting access it should not have.

## Development

```bash
swift build
swift test --parallel
swiftlint lint --strict
```

CI builds the library for iOS, tvOS, watchOS and visionOS simulators, cross-builds for iOS 15, runs the tests on macOS, builds the example app and checks that a fresh package can depend on it.

## Security

Report vulnerabilities to cagatayegilmez08@gmail.com. Please do not open a public issue for them.

## License

Apache License 2.0. Copyright 2026 Çağatay Eğilmez. See [LICENSE](LICENSE).
