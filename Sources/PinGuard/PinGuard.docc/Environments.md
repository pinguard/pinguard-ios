# Environments

Register one policy set per deployment environment and switch between them at runtime.

## Overview

Development, UAT and production servers rarely share certificates. Instead of rebuilding the configuration every time you point the app elsewhere, you register a ``PinGuardEnvironmentConfiguration`` for each ``PinGuardEnvironment`` and select the active one. Switching later is a single `await`.

## Registering environments

``PinGuardBuilder`` collects environments and picks the current one:

```swift
await PinGuard.configure { builder in
    builder.environment(.dev, policySet: devPolicies)
    builder.environment(.uat, policySet: uatPolicies)
    builder.environment(.prod, policySet: prodPolicies, mtls: prodMTLS)
    builder.selectEnvironment(.prod)
}
```

Each environment carries its own ``PolicySet`` and, optionally, its own ``MTLSConfiguration``. Event sinks are shared across environments because they belong to the ``PinGuardConfiguration`` as a whole.

`.dev`, `.uat` and `.prod` are provided for convenience. ``PinGuardEnvironment`` is expressible by a string literal, so any name works:

```swift
builder.environment("staging", policySet: stagingPolicies)
builder.selectEnvironment("staging")
```

If you never call ``PinGuardBuilder/selectEnvironment(_:)``, the current environment is `.prod`.

## Switching at runtime

``PinGuardConfiguration`` is a plain value. Read it, change `current`, write it back:

```swift
var configuration = await PinGuard.shared.currentConfiguration
configuration.current = .dev
await PinGuard.shared.update(configuration: configuration)
```

The delegate reads the active policy set and mTLS settings on every challenge, so the switch takes effect on the next request. You don't need a new `URLSession`.

## What happens with an unknown environment

Selecting an environment that was never registered is not an error. The active policy set becomes an empty ``PolicySet`` with no default, which means every host produces `policyMissing` and every connection is cancelled. If all requests start failing right after a switch, check the environment name first.

## Environments and remote configuration

``PinGuard/PinGuard/apply(remoteConfig:verifier:to:)`` replaces the policy set of one environment and keeps its mTLS settings. By default it targets the current environment, but you can name another one, for example to prepare production pins while the app is still pointed at UAT. See <doc:RemoteConfiguration>.
