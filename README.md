# PinGuard

Production-grade TLS certificate pinning and optional mTLS for iOS 15+, macOS 12+, tvOS 15+, watchOS 8+, and visionOS 1+.

Zero external dependencies. Uses only Foundation, Security, and OSLog.

## Features

✅ **SPKI/Certificate Pinning** - SHA256 pinning of SubjectPublicKeyInfo or full certificates
✅ **Rotation Support** - Primary + backup pins for safe key rotation
✅ **Wildcard Hosts** - Safe wildcard matching (*.example.com matches only api.example.com, not a.b.example.com)
✅ **Fail Strategies** - Strict or permissive modes with optional system trust fallback
✅ **mTLS Skeleton** - Client certificate authentication with PKCS12/Keychain support
✅ **Observability** - OSLog integration + custom telemetry callbacks
✅ **iOS 15+ async/await** - Modern URLSession API
✅ **Thread-Safe** - Works from any thread, no MainActor constraints on evaluate()
✅ **Remote Config** - HMAC/PublicKey signature verification for dynamic pin updates

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/pinguard/pinguard-ios.git", from: "1.0.0")
]
```

Or in Xcode:
File → Add Package Dependencies → `https://github.com/pinguard/pinguard-ios.git`

**Products:**
- `PinGuard` - Main library

## Quickstart

```swift
import PinGuard

// 1. Define pins (get hash by running: openssl x509 -pubkey -noout < cert.pem | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64)
let primaryPin = Pin(type: .spki, hash: "Y7EKzelfzqmyMnNRDIX8cecAf6wj1nk7nT25ws/qnVo=", role: .primary)
let backupPin = Pin(type: .spki, hash: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", role: .backup)

// 2. Create policy
let policy = PinningPolicy(
    pins: [primaryPin, backupPin],
    failStrategy: .strict,
    requireSystemTrust: true,
    allowSystemTrustFallback: false
)

// 3. Configure PinGuard
PinGuard.configure { builder in
    let policySet = PolicySet(policies: [
        HostPolicy(pattern: .exact("api.example.com"), policy: policy),
        HostPolicy(pattern: .wildcard("example.com"), policy: policy)
    ])
    builder.environment(.prod, policySet: policySet)
    builder.selectEnvironment(.prod)
    builder.telemetry { event in
        print("PinGuard event: \(event)")
    }
}

// 4. Use PinGuardSession for requests (iOS 15+ async/await)
let session = PinGuardSession()
let (data, response) = try await session.data(from: URL(string: "https://api.example.com")!)
```

## Policy Examples

### Strict SPKI Pinning (Recommended)

```swift
let pin = Pin(type: .spki, hash: "base64Hash", role: .primary)
let policy = PinningPolicy(
    pins: [pin],
    failStrategy: .strict,           // Reject on pin mismatch
    requireSystemTrust: true,         // Also verify system trust
    allowSystemTrustFallback: false   // Don't fall back if pins fail
)
```

### Certificate Pinning

```swift
let pin = Pin(type: .certificate, hash: "base64CertHash")
let policy = PinningPolicy(pins: [pin])
```

### CA/Intermediate Pinning

```swift
let caPin = Pin(type: .ca, hash: "base64Hash", scope: .root)
let intermediatePin = Pin(type: .spki, hash: "base64Hash", scope: .intermediate)
let policy = PinningPolicy(pins: [caPin, intermediatePin])
```

**Note:** CA pinning is less secure than leaf pinning. Use with caution and document limitations.

### Permissive Mode (Development)

```swift
let policy = PinningPolicy(
    pins: [devPin],
    failStrategy: .permissive,  // Allow system trust on pin mismatch
    requireSystemTrust: true
)
```

### System Trust Fallback

```swift
let policy = PinningPolicy(
    pins: [pin],
    failStrategy: .strict,
    requireSystemTrust: true,
    allowSystemTrustFallback: true  // Fall back to system trust if pins fail
)
```

**Warning:** Fallback weakens security. Use only during gradual rollout.

## Rotation

Safe key rotation requires shipping both old and new pins:

```swift
// Step 1: Ship v1.0 with both pins
let currentPin = Pin(type: .spki, hash: "oldKeyHash", role: .primary)
let nextPin = Pin(type: .spki, hash: "newKeyHash", role: .backup)
let policy = PinningPolicy(pins: [currentPin, nextPin])

// Step 2: After v1.0 adoption, rotate server key to newKey

// Step 3: Ship v1.1 swapping primary/backup
let currentPin = Pin(type: .spki, hash: "newKeyHash", role: .primary)
let nextPin = Pin(type: .spki, hash: "futureKeyHash", role: .backup)

// Step 4: After v1.1 adoption, remove oldKeyHash
```

**Best Practice:** Always maintain at least 2 pins (primary + backup) to enable rotation.

## mTLS (Client Certificates)

### Basic Setup

```swift
let provider = StaticClientCertificateProvider(
    source: .pkcs12(data: p12Data, password: "secret")
)
let mtlsConfig = MTLSConfiguration(
    provider: provider,
    onRenewalRequired: {
        print("Client certificate expired, trigger renewal")
    }
)

PinGuard.configure { builder in
    builder.environment(.prod, policySet: policySet, mtls: mtlsConfig)
    builder.selectEnvironment(.prod)
}
```

### Keychain Source

```swift
let provider = StaticClientCertificateProvider(
    source: .keychain(identityTag: "com.example.client-cert".data(using: .utf8)!)
)
```

### Custom Provider

```swift
struct DynamicProvider: ClientCertificateProvider {
    func clientIdentity(for host: String) -> ClientIdentityResult {
        // Load certificate based on host
        if host == "api.example.com" {
            return .success(identity: identity, certificateChain: chain)
        }
        return .unavailable
    }
}
```

## Remote Config Verification

### HMAC Verification

```swift
let verifier = HMACRemoteConfigVerifier { secretID in
    // Securely fetch HMAC key for secretID (from Keychain, not hardcoded)
    return fetchSecretFromKeychain(secretID)
}

let blob = RemoteConfigBlob(
    payload: jsonData,
    signature: hmacSignature,
    signatureType: .hmacSHA256(secretID: "prod-v1")
)

guard verifier.verify(blob: blob) else {
    print("⚠️ Invalid signature, rejecting remote config")
    return
}

// Safe to decode payload
let newPolicySet = try JSONDecoder().decode(PolicySet.self, from: blob.payload)
```

### Public Key Verification

```swift
let verifier = PublicKeyRemoteConfigVerifier { keyID in
    // Return SecKey for keyID (embedded in app or fetched securely)
    return publicKeyForID(keyID)
}

let blob = RemoteConfigBlob(
    payload: jsonData,
    signature: ecdsaSignature,
    signatureType: .publicKey(keyID: "prod-signing-key")
)

guard verifier.verify(blob: blob) else {
    print("⚠️ Invalid signature")
    return
}
```

**⚠️ SECURITY WARNING:** Unsigned remote configuration allows network attackers to disable pinning. Always verify signatures.

## Observability

### OSLog (Automatic)

PinGuard automatically logs to OSLog under subsystem `PinGuard`, category `core`.

View logs in Console.app or via CLI:
```bash
log stream --predicate 'subsystem == "PinGuard"' --level debug
```

### Custom Telemetry

```swift
PinGuard.configure { builder in
    builder.telemetry { event in
        switch event {
        case .pinMismatch(let host):
            analytics.trackPinMismatch(host: host)
        case .systemTrustFailed(let host, let error):
            analytics.trackTrustFailure(host: host, error: error)
        default:
            break
        }
    }
}
```

### Events

- `policyMissing(host:)` - No policy configured for host
- `systemTrustEvaluated(host:isTrusted:)` - System trust result
- `systemTrustFailed(host:error:)` - System trust failed
- `pinMatched(host:pins:)` - Pins validated successfully
- `pinMismatch(host:)` - Pin validation failed
- `chainSummary(host:summary:)` - Certificate chain info (domains redacted)
- `mtlsIdentityUsed(host:)` - Client cert sent
- `mtlsIdentityMissing(host:)` - Client cert unavailable

## Troubleshooting

### `policyMissing` error

**Cause:** No policy configured for the requested host.

**Solution:**
- Verify host matches exactly (case-insensitive): `api.example.com` vs `API.example.com`
- Check wildcard pattern: `*.example.com` matches `api.example.com` but NOT `example.com` or `a.b.example.com`
- Ensure policy is added: `HostPolicy(pattern: .exact("api.example.com"), policy: policy)`

### `pinMismatch` error

**Cause:** Certificate in chain doesn't match any configured pin.

**Solution:**
1. Verify pin hash is correct:
   ```bash
   # For SPKI hash:
   openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64

   # For certificate hash:
   openssl x509 -in cert.pem -outform der | openssl dgst -sha256 -binary | openssl enc -base64
   ```
2. Check certificate scope: leaf/intermediate/root
3. Ensure pin type matches: `.spki` for public key, `.certificate` for full cert
4. Verify chain includes the pinned certificate (check in browser dev tools)

### `systemTrustFailed` error

**Cause:** System trust evaluation failed.

**Solution:**
- Check certificate validity dates (not expired, not future-dated)
- Verify certificate chain is complete
- Check for clock skew on device
- Ensure ATS (App Transport Security) requirements are met
- Test with `requireSystemTrust: false` to isolate issue

### Build errors with SecIdentity

**Cause:** Swift 6 strict concurrency checking.

**Solution:** Already handled in PinGuard (uses CFTypeID comparison internally).

## Limitations & Threat Model

### What PinGuard Protects Against

✅ Rogue/compromised Certificate Authorities
✅ TLS man-in-the-middle attacks (when pins are correct)
✅ Certificate substitution attacks

### What PinGuard Does NOT Protect Against

❌ **Application compromise** - If attacker controls your app, they can bypass pinning
❌ **Unsigned remote config** - Network attacker can disable pinning if config is unsigned
❌ **Physical device compromise** - Root/jailbreak with runtime hooks can bypass pins
❌ **Binary patching** - Attacker modifying app binary can remove pinning
❌ **Certificate Transparency** - Not implemented (optional, consider adding)
❌ **OCSP stapling** - Not checked (relies on system behavior)

### Design Decisions

- **No jailbreak detection** - Security theater; easily bypassed and causes false positives
- **No debugger detection** - Hinders legitimate debugging, doesn't prevent skilled attackers
- **No TLS fingerprinting** - Out of scope, adds complexity
- **No obfuscation** - Provides false sense of security

### CA/Intermediate Pinning Caveat

Pinning CA or intermediate certificates is less secure than leaf pinning because:
- CA can issue certificates for any domain
- Compromise of CA private key affects all pins
- Rotation is harder (affects multiple services)

**Recommendation:** Pin leaf certificates (SPKI preferred) whenever possible.

## Architecture

```
PinGuard (main library)
├── Core
│   ├── TrustEvaluator       - SecTrust evaluation engine
│   ├── PinningPolicy        - Policy models (Pin, HostPattern, PolicySet)
│   ├── HostMatcher          - Wildcard matching logic
│   ├── PinHasher            - SPKI/cert hash computation (ASN.1 encoding)
│   └── Errors               - Error types and TrustDecision
├── Networking
│   ├── PinGuardURLSessionDelegate - Challenge handler
│   └── PinGuardSession      - Async/await URLSession wrapper
├── TLS
│   ├── MTLSConfiguration    - Client certificate config
│   └── ClientCertificate    - PKCS12/Keychain loading
├── Utils
│   └── Logger               - OSLog integration
└── Public
    ├── PinGuard             - Main configuration API
    └── RemoteConfigVerification - Signature verification
```

## Public API Summary

### Configuration

```swift
PinGuard.configure { builder in
    builder.environment(.prod, policySet: policySet, mtls: mtlsConfig)
    builder.selectEnvironment(.prod)
    builder.telemetry { event in }
}
```

### Pin Types

- `.spki` - Pin public key (SubjectPublicKeyInfo) - **Recommended**
- `.certificate` - Pin full certificate (DER)
- `.ca` - Pin CA certificate (use with caution)

### Fail Strategies

- `.strict` - Reject on pin mismatch (production default)
- `.permissive` - Allow system trust on pin mismatch (development/gradual rollout)

### Host Patterns

- `.exact("api.example.com")` - Exact match only
- `.wildcard("example.com")` - Matches `*.example.com` (single label only)

### URLSession Integration

```swift
// Async/await (iOS 15+)
let session = PinGuardSession()
let (data, response) = try await session.data(from: url)
let (data, response) = try await session.data(for: request)

// Custom delegate
let delegate = PinGuardURLSessionDelegate(pinGuard: .shared, mtls: mtlsConfig)
let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
```

## Example App

See `Example/` directory for a working iOS app demonstrating:
- Pin validation success
- Pin validation failure
- Rotation scenarios
- mTLS configuration

Run:
```bash
cd Example
open Example.xcodeproj
```

## Requirements

- **iOS 15.0+** / macOS 12.0+ / tvOS 15.0+ / watchOS 8.0+ / visionOS 1.0+
- **Xcode 15+** (Swift 6)
- **No external dependencies**

## License

Apache-2.0

## Credits

Built by Çağatay Eğilmez
