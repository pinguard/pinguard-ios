//
//  ClientIdentityResult.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Security

public enum ClientIdentityResult {

    /// A client identity and its certificate chain were successfully retrieved.
    case success(identity: SecIdentity, certificateChain: [SecCertificate])

    /// A client identity is required but must be renewed or re-provisioned.
    case renewalRequired

    /// No client identity is available for the request.
    case unavailable
}
