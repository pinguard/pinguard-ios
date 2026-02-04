import Foundation
import Security

public enum ClientCertificateSource: Sendable {
    
    case pkcs12(data: Data, password: String)
    case keychain(identityTag: Data)
}

public struct ClientCertificateLoader {
    
    public static func loadIdentity(from source: ClientCertificateSource) -> ClientIdentityResult {
        switch source {
        case .pkcs12(let data, let password):
            return loadPKCS12(data: data, password: password)
        case .keychain(let identityTag):
            return loadFromKeychain(tag: identityTag)
        }
    }
    
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
    
    public func clientIdentity(for host: String) -> ClientIdentityResult {
        ClientCertificateLoader.loadIdentity(from: source)
    }
}
