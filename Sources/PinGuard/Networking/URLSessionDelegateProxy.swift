import Foundation

public final class PinGuardSession {
    private let session: URLSession

    public init(configuration: URLSessionConfiguration = .default, pinGuard: PinGuard, mtls: MTLSConfiguration? = nil) {
        let delegate = PinGuardURLSessionDelegate(pinGuard: pinGuard, mtls: mtls)
        self.session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    }

    @MainActor
    public convenience init(configuration: URLSessionConfiguration = .default) {
        let config = PinGuard.shared.currentConfiguration()
        self.init(configuration: configuration, pinGuard: .shared, mtls: config.activeMTLS)
    }

    public func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await session.data(for: request)
    }

    public func data(from url: URL) async throws -> (Data, URLResponse) {
        try await session.data(from: url)
    }
}

