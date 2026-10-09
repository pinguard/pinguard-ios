//
//  PinGuardEventSink.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

/// A destination for PinGuard events, such as a logger or an analytics client.
public protocol PinGuardEventSink: Sendable {

    /// Handles a single emitted event.
    ///
    /// - Parameter event: The event that was emitted.
    func receive(_ event: PinGuardEvent)
}
