//
//  RecordingEventSink.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Foundation
@testable import PinGuard

final class RecordingEventSink: PinGuardEventSink, @unchecked Sendable {

    private let lock = NSLock()
    private var storage: [PinGuardEvent] = []

    var events: [PinGuardEvent] {
        lock.withLock {
            storage
        }
    }

    /// Appends the event to the recorded list.
    ///
    /// - Parameter event: The event that was emitted.
    func receive(_ event: PinGuardEvent) {
        lock.withLock {
            storage.append(event)
        }
    }
}
