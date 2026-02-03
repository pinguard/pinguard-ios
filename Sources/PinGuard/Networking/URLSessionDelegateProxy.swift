import Foundation

final class PinGuardSession {

    private let session: URLSession

    init(configuration: URLSessionConfiguration = .default,
         pinGuard: PinGuard,
         mtls: MTLSConfiguration? = nil) {
        let delegate = PinGuardURLSessionDelegate(pinGuard: pinGuard, mtls: mtls)
        self.session = URLSession(configuration: configuration,
                                  delegate: delegate,
                                  delegateQueue: nil)
    }

    @MainActor
    convenience init(configuration: URLSessionConfiguration = .default) {
        let config = PinGuard.shared.currentConfiguration()
        self.init(configuration: configuration, pinGuard: .shared, mtls: config.activeMTLS)
    }

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await session.data(for: request)
    }

    func data(from url: URL) async throws -> (Data, URLResponse) {
        try await session.data(from: url)
    }
}
