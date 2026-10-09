# Security Model

What certificate pinning protects you from, what it does not, and the decisions PinGuard makes on your behalf.

## Overview

Pinning is a narrow tool. It is very good at one job and useless for several others that people often expect from it. This article draws the line so you can decide where PinGuard fits in your threat model.

## What pinning protects against

TLS normally trusts any certificate that chains to one of the hundreds of root authorities in the system trust store. Pinning shrinks that set to the keys you chose. In practice this stops three things.

The first is a compromised or careless authority. If any public CA issues a certificate for your domain to someone else, the system accepts it, PinGuard does not.

The second is a user installed root certificate. Corporate proxies and debugging tools install their own root and re sign every site. The system trusts them once the user says yes. The pin does not match, so PinGuard cancels the connection.

The third is hijacked DNS combined with a valid certificate. An attacker who redirects your hostname still needs a certificate whose key matches your pin, and they don't have your private key.

## What pinning does not protect against

Pinning only decides whether a connection is allowed. It knows nothing about who is running the app.

A compromised device or a patched binary is out of scope. If an attacker controls the app, they control the pins. PinGuard does not detect jailbreaks or tampering, and it would be wrong to rely on it for that.

Traffic that does not go through the delegate is not pinned. That includes a `WKWebView`, a third party SDK with its own `URLSession`, and any request you made before configuration finished.

Unsigned remote configuration is refused on purpose. PinGuard has no code path that applies a configuration without a verifier. If you decode the JSON yourself and call ``PinGuard/PinGuard/update(configuration:)``, you have moved the trust decision to your backend and to anyone who can impersonate it.

Problems the system already catches are not PinGuard's job. Expired certificates, wrong hostnames and revoked chains are rejected by the operating system before pins are compared, as long as `requireSystemTrust` stays `true`.

## How a decision is made

Every challenge follows the same path. We walk through it here because the order matters when you read events later:

1. The host is normalized and matched against your policies. No match and no default policy means `policyMissing` and the connection is cancelled.
2. The operating system evaluates the chain against the SSL policy for the host. With `requireSystemTrust` set to `true` and a `.strict` policy, a failure ends the evaluation with `systemTrustFailed`.
3. The chain the system built is read back and every certificate in it becomes a candidate with a leaf, intermediate or root scope.
4. Each pin is compared against the candidates its scope allows. One match is enough and produces `pinMatched`.
5. If nothing matched, the policy's relaxing switches decide. `allowSystemTrustFallback` accepts the connection when the system trusted the chain. A `.permissive` policy does the same. Otherwise the connection is cancelled with `pinMismatch`.

The same logic runs for the shared instance, for your own ``PinGuard/PinGuard`` instance and for a standalone ``TrustEvaluator``.

## Why the defaults are strict

A new ``PinningPolicy`` requires system trust, uses the `.strict` strategy and does not fall back. Those defaults are the only combination where a pin mismatch actually stops an attacker. The relaxing switches exist for one reason: to roll pinning out gradually while you watch the events, then tighten.

**Important:** `.permissive` and `allowSystemTrustFallback` turn a security control into a logging control. Keep them out of production builds.

## Key rotation

Certificates expire and keys get rotated. A pin on the public key survives a renewal that keeps the key, which is why `.spki` is the recommended ``PinType``. For the day the key itself changes you need a second pin that already points at the new key, which is the `.backup` ``PinRole``. Generate the backup key pair ahead of time, pin its public key, and keep the private key offline until you need it.

If you cannot predict the next key, <doc:RemoteConfiguration> lets you ship new pins without an app release, as long as the configuration is signed.

## What ends up in the logs

Events carry the hostname you connected to. Certificate subject names are reduced to a `*.example.com` shape and only the count of Subject Alternative Names is reported, see ``ChainSummary``. Nothing in an event identifies the user, so forwarding events to analytics is safe by default. See <doc:EventsAndLogging> for the full list.
