# PinGuard

[![Swift](https://img.shields.io/badge/Swift-5.9+-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%20|%20macOS%20|%20tvOS%20|%20watchOS%20|%20visionOS-blue.svg)](https://developer.apple.com)
[![SPM](https://img.shields.io/badge/SPM-Compatible-brightgreen.svg)](https://swift.org/package-manager)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

TLS pinning + optional mTLS for Apple platforms, distributed via Swift Package Manager.

## What PinGuard Is

PinGuard is a certificate pinning SDK that validates server certificates against pre-configured cryptographic pins (hashes). It integrates with `URLSession` to prevent man-in-the-middle attacks by rejecting connections to servers whose certificates don't match your pins—even if the certificates are signed by trusted certificate authorities.

### What PinGuard Is NOT

- **Not** a general-purpose TLS stack or networking library
- **Not** protection against application compromise, jailbreak hooks, or binary patching
- **Not** a replacement for proper server authentication and HTTPS
- **Not** protection if remote configuration is unsigned (network attackers can disable pinning)

## Threat Model

### Protects Against

✅ Rogue or compromised Certificate Authorities issuing certificates for your domains
✅ Man-in-the-middle attacks with valid but unauthorized certificates
✅ Certificate substitution attacks on the network path

### Does NOT Protect Against

❌ Application compromise (if attacker controls your app, they control pinning)
❌ Unsigned remote configuration updates (allows disabling pinning over the network)
❌ Physical device compromise with runtime instrumentation (jailbreak + Frida/LLDB)
❌ Binary patching or code modification attacks

**Design principle:** PinGuard provides strong network-level protection when integrated correctly. It does not attempt security theater like jailbreak detection or code obfuscation, which are easily bypassed and cause false positives.

## Features

- **SPKI & Certificate Pinning** – SHA256 hashing of SubjectPublicKeyInfo (public keys) or full certificates
- **Pin Rotation** – Primary + backup pins for safe key rotation without app updates
- **Wildcard Hosts** – Safe single-label wildcard matching (`*.example.com` matches `api.example.com` but NOT `a.b.example.com`)
- **Fail Strategies** – Strict (reject on mismatch) or permissive (allow system trust fallback)
- **mTLS Support** – Client certificate authentication with PKCS12 and Keychain support
- **Remote Config** – HMAC-SHA256 and ECDSA signature verification for dynamic pin updates
- **Observability** – OSLog integration + custom telemetry callbacks for all events
- **Thread-Safe** – All operations can be called from any thread
- **Async/await** – Modern URLSession integration (iOS 15+)
- **Multi-Environment** – Configure separate policies for dev/staging/production

## Requirements

| Requirement | Version |
|------------|---------|
| **iOS** | 15.0+ |
| **macOS** | 12.0+ |
| **tvOS** | 15.0+ |
| **watchOS** | 8.0+ |
| **visionOS** | 1.0+ |
| **Xcode** | 15.0+ |
| **Swift** | 5.9+ (built with Swift 6 concurrency) |

**Dependencies:** None (uses only `Foundation`, `Security`, `CryptoKit`, `OSLog`)

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/pinguard/pinguard-ios.git", from: "0.1.0")
]
```

Then add the `PinGuard` product to your target dependencies.

## Quick Start (3 minutes)

### 1) Configure PinGuard once at app startup

```swift
import PinGuard

enum PinGuardBootstrap {
    static func configure() {
        let primary = Pin(type: .spki, hash: "PRIMARY_BASE64_SHA256_HASH", role: .primary)
        let backup = Pin(type: .spki, hash: "BACKUP_BASE64_SHA256_HASH", role: .backup)

        let policy = PinningPolicy(
            pins: [primary, backup],
            failStrategy: .strict,
            requireSystemTrust: true,
            allowSystemTrustFallback: false
        )

        let policySet = PolicySet(policies: [
            HostPolicy(pattern: .exact("api.example.com"), policy: policy),
            HostPolicy(pattern: .wildcard("example.com"), policy: policy)
        ])

        PinGuard.configure { builder in
            builder.environment(.prod, policySet: policySet)
            builder.selectEnvironment(.prod)
        }
    }
}
```

### 2) SwiftUI usage (copy-paste runnable)

```swift
import PinGuard
import SwiftUI

@main
struct DemoApp: App {
    init() {
        PinGuardBootstrap.configure()
    }

    var body: some Scene {
        WindowGroup { ContentView() }
    }
}

struct ContentView: View {
    var body: some View {
        Button("Load profile") {
            Task {
                do {
                    let session = PinGuardSession()
                    let url = URL(string: "https://api.example.com/v1/profile")!
                    let (_, response) = try await session.data(from: url)
                    print(response)
                } catch {
                    print("Request failed:", error)
                }
            }
        }
    }
}
```

### 3) UIKit usage (AppDelegate/Scene)

```swift
import PinGuard
import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        PinGuardBootstrap.configure()
        return true
    }
}
```

## Integration Guide

### Pinning policy model

- `PinType`: `.spki`, `.certificate`, `.ca`
- `PinRole`: `.primary`, `.backup`
- `PinScope`: `.leaf`, `.intermediate`, `.root`, `.any`
- `FailStrategy`: `.strict`, `.permissive`

```swift
let pin = Pin(type: .spki, hash: "BASE64_SHA256_HASH", role: .primary, scope: .any)
let policy = PinningPolicy(
    pins: [pin],
    failStrategy: .strict,
    requireSystemTrust: true,
    allowSystemTrustFallback: false
)
```

### Host mapping and wildcard behavior

```swift
let policySet = PolicySet(policies: [
    HostPolicy(pattern: .exact("api.example.com"), policy: apiPolicy),
    HostPolicy(pattern: .wildcard("example.com"), policy: wildcardPolicy)
])
```

- `*.example.com` matches `api.example.com`
- `*.example.com` does not match `example.com`
- `*.example.com` does not match `a.b.example.com`

### Environments and runtime selection

```swift
PinGuard.configure { builder in
    builder.environment(.dev, policySet: devPolicySet)
    builder.environment(.prod, policySet: prodPolicySet)
    builder.selectEnvironment(.prod)
}
```

### URLSession integration

#### Convenience wrapper

```swift
let session = PinGuardSession()
let (data, response) = try await session.data(from: URL(string: "https://api.example.com")!)
```

#### Custom delegate

```swift
let delegate = PinGuardURLSessionDelegate(pinGuard: .shared)
let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
```

## mTLS example

```swift
let provider = StaticClientCertificateProvider(
    source: .pkcs12(data: p12Data, password: "p12-password")
)

let mtls = MTLSConfiguration(provider: provider, onRenewalRequired: {
    // trigger renewal flow
})

PinGuard.configure { builder in
    builder.environment(.prod, policySet: policySet, mtls: mtls)
    builder.selectEnvironment(.prod)
}
```

## Telemetry example (PII-safe)

```swift
PinGuard.configure { builder in
    builder.environment(.prod, policySet: policySet)
    builder.selectEnvironment(.prod)
    builder.telemetry { event in
        switch event {
        case .pinMismatch(let host):
            print("pin_mismatch host=\(host)")
        case .systemTrustFailed(let host, _):
            print("system_trust_failed host=\(host)")
        default:
            break
        }
    }
}
```

## Troubleshooting

### `policyMissing(host:)`
- No matching `HostPolicy`.
- Confirm exact host and wildcard scope.

### `pinMismatch(host:)`
- Verify pin type (`.spki` vs `.certificate`) and base64 hash.
- Keep at least two pins (`primary` + `backup`) for rotation.

### `systemTrustFailed(host:error:)`
- Check cert validity dates and chain completeness.
- Confirm ATS/TLS server configuration.

## Security notes

- SPKI pinning is recommended for stable rotations.
- `allowSystemTrustFallback` weakens pinning and is for controlled rollout only.
- Unsigned remote config is insecure. Always verify signatures.

## Lint contract

Run lint locally:

```bash
swiftlint lint
```

Run autocorrect safely (review diffs before commit):

```bash
swiftlint --fix && swiftlint lint
```

### Event Types

| Event | Description |
|-------|-------------|
| `policyMissing(host:)` | No policy configured for host |
| `systemTrustEvaluated(host:isTrusted:)` | System trust evaluation result |
| `systemTrustFailed(host:error:)` | System trust evaluation failed |
| `systemTrustFailedPermissive(host:)` | Trust failed but permissive mode allowed it |
| `chainSummary(host:summary:)` | Certificate chain metadata (domains redacted) |
| `pinMatched(host:pins:)` | Pin validation succeeded |
| `pinMismatch(host:)` | Pin validation failed |
| `pinMismatchAllowedByFallback(host:)` | Pin mismatch but fallback allowed connection |
| `pinMismatchPermissive(host:)` | Pin mismatch accepted by permissive mode |
| `pinSetEmpty(host:)` | Policy has no pins configured |
| `mtlsIdentityUsed(host:)` | Client certificate was sent |
| `mtlsIdentityMissing(host:)` | Client certificate required but unavailable |

## Security

**Reporting vulnerabilities:** Email cagatayegilmez08@gmail.com (do not open public issues for security vulnerabilities).

**Security best practices when using PinGuard:**
1. Always use signed remote configuration (never unsigned)
2. Store HMAC secrets in Keychain (never hardcode)
3. Embed public keys for signature verification (never fetch dynamically without prior verification)
4. Monitor telemetry for unexpected pin mismatches
5. Implement fallback strategies carefully (gradual rollout only, not permanent)
6. Use `.strict` mode in production
7. Rotate pins regularly (every 12-18 months)

## License

Apache License 2.0

Copyright 2026 Çağatay Eğilmez

See [LICENSE](LICENSE) for full license text.

---

**Built by** Çağatay Eğilmez
**Repository:** [github.com/pinguard/pinguard-ios](https://github.com/pinguard/pinguard-ios)
