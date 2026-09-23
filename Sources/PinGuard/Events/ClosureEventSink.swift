//
//  ClosureEventSink.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

public struct ClosureEventSink: PinGuardEventSink {

    private let handler: @Sendable (PinGuardEvent) -> Void

    public init(_ handler: @escaping @Sendable (PinGuardEvent) -> Void) {
        self.handler = handler
    }

    /// Forwards the event to the wrapped closure.
    ///
    /// - Parameter event: The event that was emitted.
    public func receive(_ event: PinGuardEvent) {
        handler(event)
    }
}
