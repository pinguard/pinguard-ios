# Remote Configuration

Update pins without an app release, as long as the configuration is signed.

## Overview

Sooner or later a key rotates faster than your release cycle. Remote configuration lets the backend send a new ``PolicySet`` to the app. PinGuard verifies the signature, decodes the JSON and swaps the policy set of one environment. If any step fails, nothing changes.

**Important:** An unsigned remote configuration would let a network attacker switch pinning off. PinGuard has no code path that applies a configuration without a ``RemoteConfigVerifier``, and ``RemoteConfigThreatModel/unsignedConfigWarning`` exists so you can show the same warning in your own tooling.

## The payload

The backend sends a JSON document shaped like ``RemoteConfigPayload``. Patterns are written as single strings, `*.example.com` for a wildcard. Fields with defaults, `role`, `scope`, `failStrategy`, `requireSystemTrust` and `allowSystemTrustFallback`, can be left out:

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

`version` must be `1`, which is ``RemoteConfigPayload/currentVersion``. A different number is rejected with ``PinGuardError/unsupportedRemoteConfigVersion(_:)`` so an older app never misreads a newer format.

## The blob

The payload travels inside a ``RemoteConfigBlob`` together with its signature and the scheme used to produce it:

```swift
let blob = RemoteConfigBlob(
    payload: json,
    signature: signature,
    signatureType: .hmacSHA256(secretID: "v1")
)
```

The signature is computed over the payload bytes exactly as they are sent. Do not re serialize the JSON on the client before verifying it. ``RemoteConfigSignature`` carries an identifier so you can rotate secrets and keys without breaking older apps.

## Verifiers

Two verifiers ship with the SDK.

``HMACRemoteConfigVerifier`` checks an HMAC-SHA256 over the payload with a shared secret. You give it a closure that resolves the secret for the identifier in the blob. Keep that secret in the keychain:

```swift
let verifier = HMACRemoteConfigVerifier { secretID in
    Keychain.secret(for: secretID)
}
```

``PublicKeyRemoteConfigVerifier`` checks an ECDSA P-256 signature over SHA-256. It takes the X9.63 representation of the public key and accepts both raw and DER encoded signatures. Embed the public key in the app:

```swift
let verifier = PublicKeyRemoteConfigVerifier { keyID in
    RemoteConfigKeys.publicKey(for: keyID)
}
```

A public key is the better choice when several apps or teams consume the same configuration, because the signing key never leaves the backend. HMAC is simpler when one app and one backend share a secret.

Both verifiers return `false` when the blob's signature type does not match what they verify, so you can hand the same blob to either one. For another scheme, conform to ``RemoteConfigVerifier`` yourself.

## Applying the configuration

Hand the blob and the verifier to the actor:

```swift
try await PinGuard.shared.apply(remoteConfig: blob, verifier: verifier)
```

``PinGuard/PinGuard/apply(remoteConfig:verifier:to:)`` targets the current environment unless you name another one. It keeps the environment's mTLS settings and replaces only the policy set. On success it emits `remoteConfigApplied`. On failure it emits `remoteConfigRejected` with a description of the error, throws, and leaves the configuration exactly as it was.

The errors you can catch:

- ``PinGuardError/invalidRemoteConfigSignature``: the verifier returned `false`.
- ``PinGuardError/invalidRemoteConfigPayload``: the payload is not valid JSON for ``RemoteConfigPayload``.
- ``PinGuardError/unsupportedRemoteConfigVersion(_:)``: the version is not `1`.

## Decoding without applying

``RemoteConfigDecoder`` does the verification and decoding on its own. Use it when you want to look at the ``PolicySet`` first, store it, or merge it into a configuration you build yourself:

```swift
let policySet = try RemoteConfigDecoder(verifier: verifier).decode(blob)
```

The decoder never applies anything, so you still need ``PinGuard/PinGuard/update(configuration:)`` or ``PinGuard/PinGuard/apply(remoteConfig:verifier:to:)`` afterwards.

## Producing a signed blob on the backend

The client side is only half of the story. On the server, sign the exact bytes you will send. With HMAC in a shell this is enough to test the flow:

```bash
openssl dgst -sha256 -hmac "shared-secret" -binary payload.json | base64
```

For ECDSA, sign the payload with the private key and send either the DER signature `openssl` produces or the raw 64 byte form. The example app in the repository signs a payload on device so you can watch a valid and a tampered blob go through ``PinGuard/PinGuard/apply(remoteConfig:verifier:to:)``.
