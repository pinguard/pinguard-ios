//
//  EventDispatcherTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

@testable import PinGuard
import Testing

@Suite
struct EventDispatcherTests {

    @Test
    func deliversToEverySinkInOrder() {
        let first = RecordingEventSink()
        let second = RecordingEventSink()
        let dispatcher = EventDispatcher(sinks: [first, second])
        dispatcher.emit(.pinMismatch(host: "a"))
        dispatcher.emit(.pinSetEmpty(host: "b"))
        #expect(first.events == [.pinMismatch(host: "a"), .pinSetEmpty(host: "b")])
        #expect(second.events == first.events)
    }

    @Test
    func appendsToRunningEventList() {
        let sink = RecordingEventSink()
        var events: [PinGuardEvent] = [.policyMissing(host: "x")]
        EventDispatcher(sinks: [sink]).emit(.pinMismatch(host: "a"), into: &events)
        #expect(events == [.policyMissing(host: "x"), .pinMismatch(host: "a")])
        #expect(sink.events == [.pinMismatch(host: "a")])
    }

    @Test
    func closureSinkForwardsEvents() {
        let counter = CallCounter()
        let sink = ClosureEventSink { _ in counter.increment() }
        EventDispatcher(sinks: [sink]).emit(.pinMismatch(host: "a"))
        #expect(counter.count == 1)
    }

    @Test
    func osLogSinkAcceptsEveryEvent() {
        let sink = OSLogEventSink(subsystem: "PinGuardTests", category: "events")
        let summary = ChainSummary(leafCommonName: "*.example.com", issuerCommonName: nil, sanCount: 1)
        let events: [PinGuardEvent] = [
            .policyMissing(host: "h"), .systemTrustEvaluated(host: "h", isTrusted: true),
            .systemTrustFailed(host: "h", error: nil), .systemTrustFailedPermissive(host: "h"),
            .chainSummary(host: "h", summary: summary), .pinMatched(host: "h", pins: []),
            .pinMismatch(host: "h"), .pinMismatchAllowedByFallback(host: "h"), .pinMismatchPermissive(host: "h"),
            .pinSetEmpty(host: "h"), .mtlsIdentityUsed(host: "h"), .mtlsIdentityMissing(host: "h"),
            .remoteConfigApplied(environment: "prod"), .remoteConfigRejected(environment: "prod", error: "e")
        ]
        for event in events {
            sink.receive(event)
        }
    }
}
