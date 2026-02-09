//
//  URLSessionDelegateProxy.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation

/// A URLSession wrapper that applies PinGuard trust evaluation and optional mTLS.
///
/// `PinGuardSession` configures a `URLSession` with a delegate that enforces the app's
/// certificate pinning policies (via PinGuard) and, when provided, presents client
/// credentials for mutual TLS (mTLS).
///
/// You can initialize it directly with a `PinGuard` instance and optional `MTLSConfiguration`,
/// or use the convenience initializer to pick up the shared configuration.
public final class PinGuardSession {

    private let session: URLSession

    /// Creates a session configured with PinGuard trust evaluation and optional mTLS.
    ///
    /// - Parameters:
    ///   - configuration: The `URLSessionConfiguration` to use when creating the session. Defaults to `.default`.
    ///   - pinGuard: The `PinGuard` instance providing pinning policies and evaluation.
    ///   - mtls: Optional client credential configuration for mutual TLS (mTLS). If `nil`, no client
    ///           certificate is presented.
    public init(configuration: URLSessionConfiguration = .default,
                pinGuard: PinGuard,
                mtls: MTLSConfiguration? = nil) {
        let delegate = PinGuardURLSessionDelegate(pinGuard: pinGuard, mtls: mtls)
        self.session = URLSession(configuration: configuration,
                                  delegate: delegate,
                                  delegateQueue: nil)
    }

    /// Convenience initializer that uses the shared PinGuard configuration.
    ///
    /// - Parameter configuration: The `URLSessionConfiguration` to use. Defaults to `.default`.
    ///
    /// This initializer reads the current shared PinGuard configuration (including any active mTLS
    /// settings) and constructs a session accordingly. Marked `@MainActor` to align with typical
    /// shared configuration access patterns in UI contexts.
    @MainActor
    public convenience init(configuration: URLSessionConfiguration = .default) {
        let config = PinGuard.shared.currentConfiguration()
        self.init(configuration: configuration, pinGuard: .shared, mtls: config.activeMTLS)
    }

    /// Performs a data task for the specified URLRequest.
    ///
    /// - Parameter request: The URLRequest to execute.
    public func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await session.data(for: request)
    }

    /// Performs a data task to load the resource at the given URL.
    ///
    /// - Parameter url: The URL to fetch.
    public func data(from url: URL) async throws -> (Data, URLResponse) {
        try await session.data(from: url)
    }
}
