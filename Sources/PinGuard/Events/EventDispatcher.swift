//
//  EventDispatcher.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

struct EventDispatcher: Sendable {

    private let sinks: [any PinGuardEventSink]

    init(sinks: [any PinGuardEventSink]) {
        self.sinks = sinks
    }

    /// Delivers the event to all sinks.
    ///
    /// - Parameter event: The event to deliver.
    func emit(_ event: PinGuardEvent) {
        for sink in sinks {
            sink.receive(event)
        }
    }

    /// Delivers the event to all sinks and appends it to the running event list.
    ///
    /// - Parameters:
    ///   - event: The event to deliver.
    ///   - events: The mutable list that accumulates emitted events.
    func emit(_ event: PinGuardEvent, into events: inout [PinGuardEvent]) {
        events.append(event)
        emit(event)
    }
}
