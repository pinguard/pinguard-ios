//
//  URLSessionDelegateProxy.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation

public final class PinGuardSession {

    private let session: URLSession

    public init(configuration: URLSessionConfiguration = .default,
                pinGuard: PinGuard,
                mtls: MTLSConfiguration? = nil) {
        let delegate = PinGuardURLSessionDelegate(pinGuard: pinGuard, mtls: mtls)
        self.session = URLSession(configuration: configuration,
                                  delegate: delegate,
                                  delegateQueue: nil)
    }

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
