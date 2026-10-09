# ``PinGuard/MTLSConfiguration``

## Overview

Attach an `MTLSConfiguration` to an environment and PinGuard answers client certificate challenges for that environment. The ``provider`` supplies the identity, the optional ``onRenewalRequired`` closure is your hook for starting a re enrolment flow:

```swift
let mtls = MTLSConfiguration(provider: provider) {
    Task { await enrolment.start() }
}

builder.environment(.prod, policySet: policySet, mtls: mtls)
```

The closure is called from a `URLSession` delegate thread when the provider returns ``ClientIdentityResult/renewalRequired``, right after the `mtlsIdentityMissing` event. <doc:MutualTLS> describes the full flow.

## Topics

### Creating a configuration

- ``init(provider:onRenewalRequired:)``

### Parts

- ``provider``
- ``onRenewalRequired``
