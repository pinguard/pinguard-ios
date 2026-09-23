//
//  CertificateScope.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 10.02.2026.
//

enum CertificateScope: String {

    /// The end-entity (leaf) certificate.
    case leaf

    /// An intermediate CA certificate.
    case intermediate

    /// The root CA certificate.
    case root

    var isCA: Bool {
        self != .leaf
    }

    /// Returns whether the certificate scope is covered by the given pin scope.
    ///
    /// - Parameter scope: The pin scope to test for inclusion.
    /// - Returns: `true` when a pin with that scope may match this certificate.
    func contains(_ scope: PinScope) -> Bool {
        switch scope {
        case .any:
            return true
        case .leaf:
            return self == .leaf
        case .intermediate:
            return self == .intermediate
        case .root:
            return self == .root
        }
    }
}
