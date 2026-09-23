//
//  PinGuardSession.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import Foundation

public final class PinGuardSession: Sendable {

    private let session: URLSession

    public init(configuration: URLSessionConfiguration = .default,
                pinGuard: PinGuard = .shared) {
        let delegate = PinGuardURLSessionDelegate(pinGuard: pinGuard)
        self.session = URLSession(configuration: configuration,
                                  delegate: delegate,
                                  delegateQueue: nil)
    }

    deinit {
        session.finishTasksAndInvalidate()
    }

    /// Performs a data task for the specified URLRequest.
    ///
    /// - Parameter request: The URLRequest to execute.
    /// - Returns: The response body and metadata.
    public func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await session.data(for: request)
    }

    /// Performs a data task to load the resource at the given URL.
    ///
    /// - Parameter url: The URL to fetch.
    /// - Returns: The response body and metadata.
    public func data(from url: URL) async throws -> (Data, URLResponse) {
        try await session.data(from: url)
    }
}
