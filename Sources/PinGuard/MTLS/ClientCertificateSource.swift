//
//  ClientCertificateSource.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation

public enum ClientCertificateSource: Sendable {

    /// PKCS12 bundle containing the client identity and certificates.
    case pkcs12(data: Data, password: String)

    /// Identity stored in the Keychain, referenced by an application tag.
    case keychain(identityTag: Data)
}
