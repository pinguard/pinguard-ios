# PinGuard

[![Swift](https://img.shields.io/badge/Swift-6.0+-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%20|%20macOS%20|%20tvOS%20|%20watchOS%20|%20visionOS-blue.svg)](https://developer.apple.com)
[![SPM](https://img.shields.io/badge/SPM-Compatible-brightgreen.svg)](https://swift.org/package-manager)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

TLS certificate pinning and mutual TLS (mTLS) for Apple platforms. Zero external dependencies.

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
| **Swift** | 5.9+ (built with Swift 6) |

**Dependencies:** None (uses only `Foundation`, `Security`, `CryptoKit`, `OSLog`)

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/pinguard/pinguard-ios.git", branch: "master")
]
```

**Xcode:**
`File` → `Add Package Dependencies...` → Enter URL:
```
https://github.com/pinguard/pinguard-ios.git
```

**Available Products:**
- `PinGuard` – Main library

## Quick Start

```swift
import PinGuard

// 1. Define pins (see "Getting Pin Hashes" section below)
let primaryPin = Pin(
    type: .spki,
    hash: "Y7EKzelfzqmyMnNRDIX8cecAf6wj1nk7nT25ws/qnVo=",
    role: .primary
)
let backupPin = Pin(
    type: .spki,
    hash: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
    role: .backup
)

// 2. Create policy
let policy = PinningPolicy(
    pins: [primaryPin, backupPin],
    failStrategy: .strict,               // Reject on pin mismatch
    requireSystemTrust: true,             // Also validate system trust
    allowSystemTrustFallback: false       // Don't fall back to system trust
)

// 3. Configure PinGuard with environment support
PinGuard.configure { builder in
    let policySet = PolicySet(policies: [
        HostPolicy(pattern: .exact("api.example.com"), policy: policy),
        HostPolicy(pattern: .wildcard("example.com"), policy: policy)
    ])
    builder.environment(.prod, policySet: policySet)
    builder.selectEnvironment(.prod)
    builder.telemetry { event in
        print("PinGuard: \(event)")
    }
}

// 4. Use PinGuardSession for requests (iOS 15+)
let session = PinGuardSession()
let (data, response) = try await session.data(from: URL(string: "https://api.example.com")!)
```

## Integration Guide

### Step 1: Obtain Certificate Pin Hashes

#### For SPKI (Recommended)

```bash
# Extract SPKI hash from certificate file
openssl x509 -in cert.pem -pubkey -noout | \
  openssl pkey -pubin -outform der | \
  openssl dgst -sha256 -binary | \
  openssl enc -base64
```

#### For Full Certificate Hash

```bash
# Extract certificate hash
openssl x509 -in cert.pem -outform der | \
  openssl dgst -sha256 -binary | \
  openssl enc -base64
```

#### Get Live Server Certificate

```bash
# Fetch certificate from server
echo | openssl s_client -servername example.com -connect example.com:443 2>/dev/null | \
  openssl x509 -outform pem > example.com.pem
```

**Recommendation:** Pin SPKI (public keys) rather than certificates. SPKI pins survive certificate renewal as long as the key pair remains the same.

### Step 2: Configure Pins and Policies

```swift
import PinGuard

let pin = Pin(
    type: .spki,                    // Pin type: .spki, .certificate, .ca
    hash: "base64Hash",             // Base64-encoded SHA256 hash
    role: .primary,                 // Role: .primary or .backup
    scope: .any                     // Scope: .leaf, .intermediate, .root, .any
)

let policy = PinningPolicy(
    pins: [pin],
    failStrategy: .strict,          // .strict or .permissive
    requireSystemTrust: true,       // Validate system trust chain
    allowSystemTrustFallback: false // Fall back to system trust on pin failure
)
```

**Field Explanations:**

| Field | Options | Default | Explanation |
|-------|---------|---------|-------------|
| `type` | `.spki`, `.certificate`, `.ca` | — | What to hash and match |
| `role` | `.primary`, `.backup` | `.primary` | Supports rotation scenarios |
| `scope` | `.leaf`, `.intermediate`, `.root`, `.any` | `.any` | Which certificate in chain to match |
| `failStrategy` | `.strict`, `.permissive` | `.strict` | Reject or allow on pin mismatch |
| `requireSystemTrust` | `Bool` | `true` | Also validate system trust |
| `allowSystemTrustFallback` | `Bool` | `false` | Accept system trust if pins fail |

### Step 3: Configure Host Patterns

```swift
let policySet = PolicySet(policies: [
    // Exact match only
    HostPolicy(pattern: .exact("api.example.com"), policy: apiPolicy),

    // Single-label wildcard: matches api.example.com, NOT a.b.example.com
    HostPolicy(pattern: .wildcard("example.com"), policy: wildcardPolicy),

    // Multiple hosts
    HostPolicy(pattern: .exact("cdn.example.com"), policy: cdnPolicy)
])
```

**Wildcard Behavior:**
- `*.example.com` matches `api.example.com`, `cdn.example.com`
- `*.example.com` does NOT match `example.com` (no subdomain)
- `*.example.com` does NOT match `a.b.example.com` (multi-level subdomain)

This prevents overly broad matches that could weaken security.

### Step 4: Configure PinGuard

```swift
PinGuard.configure { builder in
    // Add environments
    builder.environment(.dev, policySet: devPolicies)
    builder.environment(.prod, policySet: prodPolicies)

    // Select active environment
    builder.selectEnvironment(.prod)

    // Optional: Add telemetry
    builder.telemetry { event in
        switch event {
        case .pinMismatch(let host):
            analytics.track("pin_mismatch", host: host)
        case .systemTrustFailed(let host, let error):
            analytics.track("trust_failed", host: host, error: error)
        default:
            break
        }
    }
}
```

### Step 5: Integrate with URLSession

#### Option A: PinGuardSession (Easiest)

```swift
// Drop-in replacement for URLSession
let session = PinGuardSession()

// Async/await (iOS 15+)
let (data, response) = try await session.data(from: url)
let (data, response) = try await session.data(for: request)
```

#### Option B: Custom Delegate

```swift
let delegate = PinGuardURLSessionDelegate(pinGuard: .shared)
let session = URLSession(
    configuration: .default,
    delegate: delegate,
    delegateQueue: nil
)

// Use session as normal
let (data, response) = try await session.data(from: url)
```

## Configuration Examples

### Production: Strict SPKI Pinning

```swift
let policy = PinningPolicy(
    pins: [primaryPin, backupPin],
    failStrategy: .strict,              // Reject on pin mismatch
    requireSystemTrust: true,           // Also validate system trust
    allowSystemTrustFallback: false     // No fallback
)
```

**Use case:** Production apps where security is critical.

### Development: Permissive Mode

```swift
let policy = PinningPolicy(
    pins: [devPin],
    failStrategy: .permissive,          // Allow system trust on mismatch
    requireSystemTrust: true
)
```

**Use case:** Development environments with self-signed certificates or frequently rotating certificates. **Do NOT use in production.**

### Gradual Rollout: System Trust Fallback

```swift
let policy = PinningPolicy(
    pins: [pin],
    failStrategy: .strict,
    requireSystemTrust: true,
    allowSystemTrustFallback: true      // Fall back to system trust
)
```

**Use case:** Initial deployment to production to monitor pin validation without breaking connections. **Weakens security—disable fallback after validation.**

### CA/Intermediate Pinning

```swift
let caPin = Pin(type: .ca, hash: "base64Hash", scope: .root)
let intermediatePin = Pin(type: .spki, hash: "base64Hash", scope: .intermediate)
let policy = PinningPolicy(pins: [caPin, intermediatePin])
```

**⚠️ Warning:** CA pinning is less secure than leaf pinning because a compromised CA can issue certificates for any domain. Use only when necessary and document the risk.

## Pin Rotation Strategy

Safe key rotation requires shipping both old and new pins before rotating server keys:

```swift
// Step 1: Ship app version 1.0 with BOTH pins
let currentPin = Pin(type: .spki, hash: "oldKeyHash", role: .primary)
let nextPin = Pin(type: .spki, hash: "newKeyHash", role: .backup)
let policy = PinningPolicy(pins: [currentPin, nextPin])

// Step 2: Wait for 90%+ adoption of version 1.0

// Step 3: Rotate server key to newKey

// Step 4: Ship app version 1.1 swapping primary/backup
let currentPin = Pin(type: .spki, hash: "newKeyHash", role: .primary)
let futurePin = Pin(type: .spki, hash: "futureKeyHash", role: .backup)

// Step 5: Wait for adoption of version 1.1, then remove oldKeyHash
```

**Best Practice:** Always maintain at least 2 pins (primary + backup) to enable rotation.

## mTLS (Mutual TLS)

PinGuard supports client certificate authentication for mTLS scenarios.

### Basic Setup with PKCS12

```swift
let provider = StaticClientCertificateProvider(
    source: .pkcs12(data: p12Data, password: "password")
)
let mtlsConfig = MTLSConfiguration(
    provider: provider,
    onRenewalRequired: {
        print("Client certificate expired—trigger renewal flow")
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

### Custom Provider (Host-Specific Certificates)

```swift
struct DynamicProvider: ClientCertificateProvider {
    func clientIdentity(for host: String) -> ClientIdentityResult {
        switch host {
        case "api.example.com":
            return loadCertificate(for: "api")
        case "backend.example.com":
            return loadCertificate(for: "backend")
        default:
            return .unavailable
        }
    }

    private func loadCertificate(for name: String) -> ClientIdentityResult {
        // Load from Keychain, filesystem, etc.
        return .success(identity: identity, certificateChain: chain)
    }
}
```

## Remote Configuration Verification

PinGuard supports dynamic pin updates via signed remote configuration. **Never use unsigned remote config—it allows network attackers to disable pinning.**

### HMAC-SHA256 Verification

```swift
let verifier = HMACRemoteConfigVerifier { secretID in
    // Fetch HMAC key securely (from Keychain, NOT hardcoded)
    return KeychainHelper.fetchSecret(for: secretID)
}

let blob = RemoteConfigBlob(
    payload: jsonData,
    signature: hmacSignature,
    signatureType: .hmacSHA256(secretID: "prod-v1")
)

guard verifier.verify(blob: blob) else {
    print("⚠️ Invalid HMAC signature—rejecting remote config")
    return
}

// Safe to decode and apply
let newPolicySet = try JSONDecoder().decode(PolicySet.self, from: blob.payload)
```

### Public Key (ECDSA) Verification

```swift
let verifier = PublicKeyRemoteConfigVerifier { keyID in
    // Return embedded public key (SecKey)
    return EmbeddedKeys.publicKey(for: keyID)
}

let blob = RemoteConfigBlob(
    payload: jsonData,
    signature: ecdsaSignature,
    signatureType: .publicKey(keyID: "prod-signing-key")
)

guard verifier.verify(blob: blob) else {
    print("⚠️ Invalid ECDSA signature—rejecting remote config")
    return
}
```

**⚠️ Security Warning:** Unsigned remote configuration is a critical vulnerability. A network attacker can send unsigned config that disables pinning entirely. Always verify signatures.

## Observability & Debugging

### OSLog Integration (Automatic)

PinGuard logs all events to OSLog under subsystem `PinGuard`, category `core`.

**View logs in Console.app** or via Terminal:

```bash
# Stream logs in real-time
log stream --predicate 'subsystem == "PinGuard"' --level debug

# View logs from last 5 minutes
log show --predicate 'subsystem == "PinGuard"' --last 5m --debug
```

### Custom Telemetry

```swift
PinGuard.configure { builder in
    builder.telemetry { event in
        switch event {
        case .pinMismatch(let host):
            analytics.track("pin_validation_failed", host: host)
        case .pinMatched(let host, let pins):
            analytics.track("pin_validation_success", host: host, pinCount: pins.count)
        case .systemTrustFailed(let host, let error):
            analytics.track("system_trust_failed", host: host, error: error)
        case .mtlsIdentityMissing(let host):
            analytics.track("mtls_unavailable", host: host)
        default:
            break
        }
    }
}
```

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

## Troubleshooting

### Error: `policyMissing`

**Cause:** No policy configured for the requested host.

**Solutions:**
1. Verify exact hostname match (case-insensitive): `api.example.com` vs `API.EXAMPLE.COM`
2. Check wildcard pattern: `*.example.com` matches `api.example.com` but NOT:
   - `example.com` (no subdomain)
   - `a.b.example.com` (multi-level subdomain)
3. Ensure `HostPolicy` is added to `PolicySet`:
   ```swift
   HostPolicy(pattern: .exact("api.example.com"), policy: policy)
   ```

### Error: `pinMismatch`

**Cause:** Server certificate doesn't match any configured pin.

**Solutions:**

1. **Verify pin hash is correct:**
   ```bash
   # For SPKI pin
   openssl x509 -in cert.pem -pubkey -noout | \
     openssl pkey -pubin -outform der | \
     openssl dgst -sha256 -binary | \
     openssl enc -base64

   # For certificate pin
   openssl x509 -in cert.pem -outform der | \
     openssl dgst -sha256 -binary | \
     openssl enc -base64
   ```

2. **Check certificate scope:**
   - `.leaf` – End-entity certificate
   - `.intermediate` – Intermediate CA
   - `.root` – Root CA
   - `.any` – Any certificate in chain (default)

3. **Verify pin type matches:**
   - `.spki` – Public key hash
   - `.certificate` – Full certificate hash

4. **Inspect server certificate chain:**
   ```bash
   openssl s_client -servername example.com -connect example.com:443 -showcerts
   ```

5. **Test in permissive mode temporarily:**
   ```swift
   let policy = PinningPolicy(pins: [pin], failStrategy: .permissive)
   ```
   If permissive mode succeeds, the issue is pin mismatch (not system trust failure).

### Error: `systemTrustFailed`

**Cause:** System trust evaluation failed (before pin validation).

**Solutions:**

1. **Check certificate validity:**
   - Certificate not expired
   - Certificate not future-dated
   - Device clock is correct

2. **Verify certificate chain is complete:**
   - Server must send intermediate certificates
   - Root certificate must be in device trust store

3. **Check App Transport Security (ATS) requirements:**
   - TLS 1.2+ required by default
   - Forward secrecy cipher suites

4. **Isolate issue by disabling system trust check temporarily:**
   ```swift
   let policy = PinningPolicy(pins: [pin], requireSystemTrust: false)
   ```
   If this succeeds, the issue is system trust (not pinning).

### Issue: Build Errors with `SecIdentity`

**Cause:** Swift 6 strict concurrency checking with Security framework types.

**Solution:** Already handled internally in PinGuard using `CFTypeID` comparison. No action required.

## API Reference

### Core Types

#### `PinGuard`

Main configuration and evaluation entry point.

```swift
// Configure
PinGuard.configure { builder in
    builder.environment(.prod, policySet: policySet)
    builder.selectEnvironment(.prod)
}

// Evaluate (usually automatic via URLSession delegate)
let decision = PinGuard.shared.evaluate(serverTrust: trust, host: host)
```

#### `Pin`

Represents a cryptographic pin.

```swift
Pin(
    type: .spki,            // .spki, .certificate, .ca
    hash: "base64Hash",     // SHA256 hash (base64)
    role: .primary,         // .primary, .backup
    scope: .any             // .leaf, .intermediate, .root, .any
)
```

#### `PinningPolicy`

Defines pinning behavior for hosts.

```swift
PinningPolicy(
    pins: [pin1, pin2],
    failStrategy: .strict,              // .strict or .permissive
    requireSystemTrust: true,           // Validate system trust
    allowSystemTrustFallback: false     // Fall back to system trust
)
```

#### `HostPattern`

Matches hostnames.

```swift
.exact("api.example.com")       // Exact match
.wildcard("example.com")        // Single-label wildcard (*.example.com)
```

#### `HostPolicy`

Associates a pattern with a policy.

```swift
HostPolicy(pattern: .exact("api.example.com"), policy: policy)
```

#### `PolicySet`

Collection of host policies.

```swift
PolicySet(
    policies: [hostPolicy1, hostPolicy2],
    defaultPolicy: fallbackPolicy  // Optional
)
```

#### `TrustDecision`

Result of trust evaluation.

```swift
struct TrustDecision {
    let isTrusted: Bool
    let reason: Reason          // .pinMatch, .systemTrustAllowed, etc.
    let events: [PinGuardEvent] // All events emitted during evaluation
}
```

### Networking

#### `PinGuardSession`

Drop-in replacement for `URLSession` with automatic pinning.

```swift
let session = PinGuardSession()
let (data, response) = try await session.data(from: url)
let (data, response) = try await session.data(for: request)
```

#### `PinGuardURLSessionDelegate`

URLSession delegate that handles authentication challenges.

```swift
let delegate = PinGuardURLSessionDelegate(pinGuard: .shared)
let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
```

### mTLS

#### `MTLSConfiguration`

Configuration for client certificate authentication.

```swift
MTLSConfiguration(
    provider: certificateProvider,
    onRenewalRequired: { /* trigger renewal flow */ }
)
```

#### `ClientCertificateProvider` (Protocol)

Provides client identities for hosts.

```swift
protocol ClientCertificateProvider {
    func clientIdentity(for host: String) -> ClientIdentityResult
}
```

#### `StaticClientCertificateProvider`

Built-in provider for static certificates.

```swift
StaticClientCertificateProvider(
    source: .pkcs12(data: p12Data, password: "password")
)
// or
StaticClientCertificateProvider(
    source: .keychain(identityTag: tagData)
)
```

### Remote Configuration

#### `RemoteConfigBlob`

Signed configuration payload.

```swift
RemoteConfigBlob(
    payload: jsonData,
    signature: signatureData,
    signatureType: .hmacSHA256(secretID: "prod-v1")
    // or .publicKey(keyID: "signing-key")
)
```

#### `HMACRemoteConfigVerifier`

Verifies HMAC-SHA256 signatures.

```swift
HMACRemoteConfigVerifier { secretID in
    return fetchSecretFromKeychain(secretID)
}
```

#### `PublicKeyRemoteConfigVerifier`

Verifies ECDSA signatures with public keys.

```swift
PublicKeyRemoteConfigVerifier { keyID in
    return embeddedPublicKey(for: keyID)
}
```

## Example App

The repository includes a comprehensive example app demonstrating all features.

**Location:** `Example/`

**Features Demonstrated:**
- Configuration & builder pattern
- Pin generation (SPKI, certificate, CA)
- Policy configuration (strict, permissive, fallback)
- Trust evaluation & decision inspection
- URLSession integration
- mTLS with PKCS12 and Keychain
- Event capture & telemetry
- Remote config verification (HMAC, public key)
- Error handling & recovery
- Environment switching

**Running the Example:**

```bash
cd Example
open Example.xcodeproj
# Select simulator and press Cmd+R
```

**Live Network Test:**
The "URLSession Integration" demo includes a live HTTPS request to `example.com` with pinning validation.

See [`Example/README.md`](Example/README.md) for detailed documentation.

## FAQ

### Q: Should I pin the leaf certificate or the CA certificate?

**A:** Pin the leaf certificate's SPKI (public key) whenever possible. CA pinning is less secure because:
- A compromised CA can issue certificates for any domain
- Rotation affects multiple services
- Single point of failure

Pin CA certificates only when you control the CA and want to simplify rotation across many services.

### Q: SPKI vs Certificate pinning—which is better?

**A:** SPKI (public key) pinning is recommended because:
- Survives certificate renewal if the key pair remains the same
- More flexible for rotation
- Smaller attack surface (pins only the cryptographic key, not the entire certificate)

Use certificate pinning only when you need to pin the entire certificate (rare).

### Q: How many pins should I configure?

**A:** Minimum 2 (primary + backup) to enable rotation. Best practice:
- Primary: Current production key
- Backup: Next rotation key or emergency key

Some organizations configure 3-4 pins for defense in depth, but more pins increase the risk of accepting an unauthorized certificate.

### Q: Can I disable pinning in debug builds?

**A:** Yes, use environment-based configuration:

```swift
#if DEBUG
let policy = PinningPolicy(pins: [devPin], failStrategy: .permissive)
#else
let policy = PinningPolicy(pins: [prodPin], failStrategy: .strict)
#endif
```

Or use separate environments:
```swift
builder.environment(.dev, policySet: permissivePolicies)
builder.environment(.prod, policySet: strictPolicies)
#if DEBUG
builder.selectEnvironment(.dev)
#else
builder.selectEnvironment(.prod)
#endif
```

### Q: What happens if my certificate rotates unexpectedly?

**A:** Pinning will fail and connections will be rejected (if `failStrategy: .strict`). This is intentional—unexpected rotation could indicate a compromise. To handle legitimate rotation:

1. **Ship backup pins in advance** (see Pin Rotation Strategy)
2. **Monitor pinning failures** via telemetry
3. **Use remote config** to update pins dynamically (with signature verification)
4. **Emergency: Ship app update** with new pins

### Q: How do I test pinning without breaking production?

**A:** Use gradual rollout strategy:

1. **Phase 1:** Deploy with `allowSystemTrustFallback: true` and monitor telemetry
2. **Phase 2:** After validating pin hashes are correct, deploy with `allowSystemTrustFallback: false`
3. **Phase 3:** After stabilization, remove fallback config entirely

### Q: Does PinGuard work with third-party domains (CDNs, APIs)?

**A:** Yes, configure separate policies for each domain:

```swift
PolicySet(policies: [
    HostPolicy(pattern: .exact("api.example.com"), policy: yourApiPolicy),
    HostPolicy(pattern: .exact("cdn.cloudflare.com"), policy: cdnPolicy),
    HostPolicy(pattern: .wildcard("amazonaws.com"), policy: awsPolicy)
])
```

Obtain pins for each service you depend on. Note: Third-party pins may rotate without notice—monitor telemetry closely.

### Q: Can I use PinGuard with WKWebView?

**A:** No. `WKWebView` does not expose hooks for custom trust evaluation. Pinning is only supported for `URLSession`-based networking. For WebView-based apps, consider:
- Server-side security (API pinning)
- Content Security Policy (CSP)
- Subresource Integrity (SRI)

### Q: What about Certificate Transparency (CT)?

**A:** PinGuard does not verify CT logs. CT validation could be added in a future version. For now, PinGuard focuses on pinning validation. CT provides transparency but does not prevent issuance of rogue certificates—pinning does.

## Versioning & Stability

PinGuard follows [Semantic Versioning](https://semver.org):

- **Major version** (X.0.0): Breaking API changes
- **Minor version** (0.X.0): New features, backward-compatible
- **Patch version** (0.0.X): Bug fixes, backward-compatible

**Current Status:** Pre-1.0 (breaking changes may occur)

**Stability Commitment:**
- Post-1.0: Breaking changes only in major versions
- Security fixes: Patched immediately in all supported major versions
- Deprecation policy: 1 major version notice before removal

**Supported Versions:**
- Only the latest major version receives active support
- Security fixes backported to previous major version for 6 months after new major release

## Contributing

We welcome contributions! See [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines.

**Before contributing:**
1. Open an issue to discuss significant changes
2. Ensure all tests pass: `swift test`
3. Follow existing code style
4. Add tests for new features
5. Update documentation

## Security

**Reporting vulnerabilities:** Email security@pinguard.dev (do not open public issues for security vulnerabilities).

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
