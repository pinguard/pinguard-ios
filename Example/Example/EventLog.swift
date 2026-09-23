//
//  EventLog.swift
//  Example
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Foundation
import PinGuard

@Observable
final class EventLog {

    private(set) var entries: [EventLogEntry] = []

    /// Appends a new entry describing the event.
    ///
    /// - Parameter event: The event PinGuard emitted.
    func append(_ event: PinGuardEvent) {
        entries.insert(EventLogEntry(date: Date(), message: event.summary), at: 0)
    }

    /// Removes every entry.
    func clear() {
        entries.removeAll()
    }
}
