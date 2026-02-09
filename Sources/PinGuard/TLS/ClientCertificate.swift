//
//  ClientCertificate.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation
import Security

public enum ClientCertificateSource: Sendable {

    /// PKCS12 bundle containing the client identity and certificates.
    ///
    /// - Parameters:
    ///   - data: The raw PKCS12 data containing the identity.
    ///   - password: The passphrase used to decrypt the PKCS12.
    case pkcs12(data: Data, password: String)

    /// Identity stored in the Keychain, referenced by an application tag.
    ///
    /// - Parameter identityTag: The application tag used to look up the identity in the Keychain.
    case keychain(identityTag: Data)
}

/// Helpers for loading client identities used for mTLS.
///
/// `ClientCertificateLoader` retrieves client identities from supported sources, such as
/// PKCS#12 blobs or the Keychain (by application tag), and returns a `ClientIdentityResult`
/// indicating success, renewal requirement, or unavailability.
public enum ClientCertificateLoader {

    /// Loads a client identity from the specified source.
    ///
    /// - Parameter source: The source from which to load the client identity.
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
    private static func loadPKCS12(data: Data, password: String) -> ClientIdentityResult {
        let options = [kSecImportExportPassphrase as String: password]
        var items: CFArray?
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &items)
        guard status == errSecSuccess, let array = items as? [[String: Any]] else {
            return .unavailable
        }

        guard let first = array.first,
              let identityRef = first[kSecImportItemIdentity as String] as CFTypeRef? else {
            return .unavailable
        }

        let identity: SecIdentity = unsafeDowncast(identityRef, to: SecIdentity.self)
        let chain = (first[kSecImportItemCertChain as String] as? [SecCertificate]) ?? []
        return .success(identity: identity, certificateChain: chain)
    }

    /// Loads a client identity from the Keychain using an application tag.
    ///
    /// - Parameter tag: The application tag associated with the stored identity.
    private static func loadFromKeychain(tag: Data) -> ClientIdentityResult {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrApplicationTag as String: tag,
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
        var cert: SecCertificate?
        _ = SecIdentityCopyCertificate(identity, &cert)
        let chain = cert.map { [$0] } ?? []
        return .success(identity: identity, certificateChain: chain)
    }
}

public struct StaticClientCertificateProvider: ClientCertificateProvider, Sendable {

    private let source: ClientCertificateSource

    public init(source: ClientCertificateSource) {
        self.source = source
    }

    /// Provides a client identity for the given host using the configured source.
    ///
    /// - Parameter host: The hostname requesting a client identity.
    public func clientIdentity(for host: String) -> ClientIdentityResult {
        ClientCertificateLoader.loadIdentity(from: source)
    }
}
