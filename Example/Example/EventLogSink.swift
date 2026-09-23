//
//  EventLogSink.swift
//  Example
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import PinGuard

nonisolated struct EventLogSink: PinGuardEventSink {

    let eventLog: EventLog

    /// Hands the event to the log on the main actor.
    ///
    /// - Parameter event: The event PinGuard emitted.
    func receive(_ event: PinGuardEvent) {
        Task {
            await eventLog.append(event)
        }
    }
}
