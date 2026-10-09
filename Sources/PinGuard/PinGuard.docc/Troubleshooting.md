# Troubleshooting

The failures people run into most often, what the events look like, and what to do about them.

## Overview

Almost every pinning problem shows up as one specific ``PinGuardEvent``. Open Console.app, filter on the `PinGuard` subsystem, reproduce the request and look for the last event before the failure. Then find it below.

## Every request fails with policyMissing

No ``HostPolicy`` matched the host and the ``PolicySet`` has no default. Three causes account for nearly all cases:

- The host in the event is not the one you wrote a pattern for. Redirects and CDN hostnames are easy to miss.
- You used `.wildcard("example.com")` and connected to `example.com` itself. A wildcard covers one extra label, not the base domain. Add an `.exact` entry.
- The active environment is not the one you registered policies for. Check `current` in ``PinGuard/PinGuard/currentConfiguration``.

If the session also loads third party content, give the set a `defaultPolicy`. See <doc:HostMatching>.

## pinMismatch right after a certificate renewal

The server's key changed and none of your pins points at the new key. This is exactly the situation the `.backup` pin exists for. Ship the new pin in an update, or use <doc:RemoteConfiguration> so the next rotation does not need a release. While you recover, `allowSystemTrustFallback: true` lets users through and keeps telling you about the mismatch.

If you only pinned `.certificate` hashes, every renewal will do this. Switch to `.spki`.

## pinMismatch on a server you know is right

Recompute the pin and compare it character by character. Common slips:

- The hash was taken from the certificate instead of the public key, or the other way round. The ``PinType`` must match how the hash was produced.
- The scope is too narrow. A `.leaf` pin cannot match an intermediate, and a `.ca` pin cannot match the leaf.
- The server presents a different certificate for the SNI you use. Run the `openssl` command from <doc:GettingStarted> with the exact `-servername`.

## systemTrustFailed on a test server

The operating system itself does not trust the chain. Typical reasons are a self signed certificate, an expired one, a hostname that is not in the Subject Alternative Names, a missing intermediate, or a leaf valid for more than 398 days. The `error` field of the event has the system's explanation.

Fix the server. Do not switch production to `.permissive` to hide it. For a local test server only, a policy with `requireSystemTrust: false` and a pin on the self signed certificate is acceptable.

## pinSetEmpty on every request

The matched policy has no pins. This is usually a default policy you added to let unknown hosts through. It is harmless when the policy is `.permissive`, but with a `.strict` policy and no fallback every request to that host is cancelled. Either give the policy pins or make it permissive on purpose.

## mtlsIdentityMissing

The server asked for a client certificate and the provider returned `.unavailable` or `.renewalRequired`. Check that the active environment has an ``MTLSConfiguration``, that the PKCS12 password is right, and that the keychain tag matches. On macOS, an unsigned test bundle cannot read the data protection keychain, so `.keychain` sources return `.unavailable` in `swift test`. That is expected.

## remoteConfigRejected

The blob failed verification or decoding. The `error` string names which. For ``PinGuardError/invalidRemoteConfigSignature``, confirm that the backend signed the exact bytes the app received and that the secret or key identifier resolves on the client. For ``PinGuardError/invalidRemoteConfigPayload``, validate the JSON against the shape in <doc:RemoteConfiguration>. For ``PinGuardError/unsupportedRemoteConfigVersion(_:)``, the backend is sending a newer format than this SDK understands.

## Requests fail before configuration finished

``PinGuard/PinGuard/configure(_:)-swift.type.method`` is `async`. A request started before it returns sees an empty configuration and fails with `policyMissing`. Await the configuration before the first request, for example in a `.task` on the root view, and make sure nothing fires a request during app initialization.

## My own URLSession never calls PinGuard

Check that the delegate is set on the session, not on the task, and that nothing else replaced it. Also note that `URLSession.shared` has no delegate and cannot be pinned. Create a session with ``PinGuardURLSessionDelegate`` or use ``PinGuardSession``.

## Nothing shows up in Console.app

Either `builder.systemLogging(false)` was called, or the filter is wrong. The subsystem is `PinGuard` and the category is `core` unless you created ``OSLogEventSink`` with other values. Debug level messages such as `systemTrustEvaluated` and `chainSummary` only appear when Console.app is set to include debug messages.
