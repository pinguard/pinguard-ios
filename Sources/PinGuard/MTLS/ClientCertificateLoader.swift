//
//  ClientCertificateLoader.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation
import Security

public enum ClientCertificateLoader {

    /// Loads a client identity from the specified source.
    ///
    /// - Parameter source: The source from which to load the client identity.
    /// - Returns: The loaded identity or `.unavailable` when it cannot be read.
    public static func loadIdentity(from source: ClientCertificateSource) -> ClientIdentityResult {
        switch source {
        case .pkcs12(let data, let password):
            return loadPKCS12(data: data, password: password)
        case .keychain(let identityTag):
            return loadFromKeychain(tag: identityTag)
        }
    }

    /// Loads a client identity from a PKCS12 data blob.
    ///
    /// - Parameters:
    ///   - data: The PKCS12 data containing the identity and certificates.
    ///   - password: The passphrase used to decrypt the PKCS12.
    /// - Returns: The loaded identity or `.unavailable` when import fails.
    private static func loadPKCS12(data: Data, password: String) -> ClientIdentityResult {
        let options = [kSecImportExportPassphrase as String: password]
        var items: CFArray?
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &items)
        guard status == errSecSuccess, let array = items as? [[String: Any]] else {
            return .unavailable
        }

        guard let first = array.first,
              let identityRef = first[kSecImportItemIdentity as String] as CFTypeRef?,
              CFGetTypeID(identityRef) == SecIdentityGetTypeID() else {
            return .unavailable
        }

        let identity: SecIdentity = unsafeDowncast(identityRef, to: SecIdentity.self)
        let chain = (first[kSecImportItemCertChain as String] as? [SecCertificate]) ?? []
        return .success(identity: identity, certificateChain: chain)
    }

    /// Loads a client identity from the Keychain using an application tag.
    ///
    /// - Parameter tag: The application tag associated with the stored identity.
    /// - Returns: The loaded identity or `.unavailable` when no match exists.
    private static func loadFromKeychain(tag: Data) -> ClientIdentityResult {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrApplicationTag as String: tag,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess,
              let identityRef = item,
              CFGetTypeID(identityRef) == SecIdentityGetTypeID() else {
            return .unavailable
        }

        let identity: SecIdentity = unsafeDowncast(identityRef, to: SecIdentity.self)
        var certificate: SecCertificate?
        _ = SecIdentityCopyCertificate(identity, &certificate)
        let chain = certificate.map { [$0] } ?? []
        return .success(identity: identity, certificateChain: chain)
    }
}
