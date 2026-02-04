//
//  PinGuardPolicyTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 2.02.2026.
//

import XCTest
@testable import PinGuard

final class PinGuardPolicyTests: XCTestCase {
    func testWildcardMatchesSingleLabel() {
        let pattern = HostPattern.parse("*.example.com")
        XCTAssertTrue(HostMatcher.matches(pattern, host: "api.example.com"))
        XCTAssertFalse(HostMatcher.matches(pattern, host: "example.com"))
        XCTAssertFalse(HostMatcher.matches(pattern, host: "a.b.example.com"))
    }

    func testPolicyResolverPrefersExact() {
        let policyExact = PinningPolicy(pins: [Pin(type: .spki, hash: "a")])
        let policyWildcard = PinningPolicy(pins: [Pin(type: .spki, hash: "b")])
        let set = PolicySet(policies: [
            HostPolicy(pattern: .wildcard("example.com"), policy: policyWildcard),
            HostPolicy(pattern: .exact("api.example.com"), policy: policyExact)
        ])
        let resolver = PolicyResolver(policySet: set)
        let resolved = resolver.resolve(host: "api.example.com")
        XCTAssertEqual(resolved?.pins.first?.hash, "a")
    }
}
