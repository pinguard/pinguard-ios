//
//  PolicyResolverTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 4.02.2026.
//

@testable import PinGuard
import XCTest

final class PolicyResolverTests: XCTestCase {

    // MARK: - Resolution Priority

    func testExactMatchTakesPriorityOverWildcard() {
        let exactPolicy = PinningPolicy(pins: [Pin(type: .spki, hash: "exact")])
        let wildcardPolicy = PinningPolicy(pins: [Pin(type: .spki, hash: "wildcard")])

        let set = PolicySet(policies: [
            HostPolicy(pattern: .wildcard("example.com"), policy: wildcardPolicy),
            HostPolicy(pattern: .exact("api.example.com"), policy: exactPolicy)
        ])

        let resolver = PolicyResolver(policySet: set)
        let resolved = resolver.resolve(host: "api.example.com")

        XCTAssertEqual(resolved?.pins.first?.hash, "exact")
    }

    func testExactMatchTakesPriorityRegardlessOfOrder() {
        let exactPolicy = PinningPolicy(pins: [Pin(type: .spki, hash: "exact")])
        let wildcardPolicy = PinningPolicy(pins: [Pin(type: .spki, hash: "wildcard")])

        let set = PolicySet(policies: [
            HostPolicy(pattern: .exact("api.example.com"), policy: exactPolicy),
            HostPolicy(pattern: .wildcard("example.com"), policy: wildcardPolicy)
        ])

        let resolver = PolicyResolver(policySet: set)
        let resolved = resolver.resolve(host: "api.example.com")

        XCTAssertEqual(resolved?.pins.first?.hash, "exact")
    }

    func testMostSpecificWildcardWins() {
        let generalPolicy = PinningPolicy(pins: [Pin(type: .spki, hash: "general")])
        let specificPolicy = PinningPolicy(pins: [Pin(type: .spki, hash: "specific")])

        let set = PolicySet(policies: [
            HostPolicy(pattern: .wildcard("com"), policy: generalPolicy),
            HostPolicy(pattern: .wildcard("example.com"), policy: specificPolicy)
        ])

        let resolver = PolicyResolver(policySet: set)
        let resolved = resolver.resolve(host: "api.example.com")

        XCTAssertEqual(resolved?.pins.first?.hash, "specific")
    }

    // MARK: - Default Policy

    func testDefaultPolicyWhenNoMatch() {
        let defaultPolicy = PinningPolicy(pins: [Pin(type: .spki, hash: "default")])
        let specificPolicy = PinningPolicy(pins: [Pin(type: .spki, hash: "specific")])

        let set = PolicySet(
            policies: [
                HostPolicy(pattern: .exact("example.com"), policy: specificPolicy)
            ],
            defaultPolicy: defaultPolicy
        )

        let resolver = PolicyResolver(policySet: set)
        let resolved = resolver.resolve(host: "other.com")

        XCTAssertEqual(resolved?.pins.first?.hash, "default")
    }

    func testNoDefaultPolicyReturnsNil() {
        let specificPolicy = PinningPolicy(pins: [Pin(type: .spki, hash: "specific")])

        let set = PolicySet(policies: [
            HostPolicy(pattern: .exact("example.com"), policy: specificPolicy)
        ])

        let resolver = PolicyResolver(policySet: set)
        let resolved = resolver.resolve(host: "other.com")

        XCTAssertNil(resolved)
    }

    // MARK: - Edge Cases

    func testEmptyHostReturnsNil() {
        let policy = PinningPolicy(pins: [Pin(type: .spki, hash: "hash")])
        let set = PolicySet(policies: [
            HostPolicy(pattern: .exact("example.com"), policy: policy)
        ])

        let resolver = PolicyResolver(policySet: set)
        let resolved = resolver.resolve(host: "")

        XCTAssertNil(resolved)
    }

    func testNoPoliciesReturnsDefault() {
        let defaultPolicy = PinningPolicy(pins: [Pin(type: .spki, hash: "default")])
        let set = PolicySet(policies: [], defaultPolicy: defaultPolicy)

        let resolver = PolicyResolver(policySet: set)
        let resolved = resolver.resolve(host: "example.com")

        XCTAssertEqual(resolved?.pins.first?.hash, "default")
    }

    func testNoPoliciesAndNoDefaultReturnsNil() {
        let set = PolicySet(policies: [])
        let resolver = PolicyResolver(policySet: set)
        let resolved = resolver.resolve(host: "example.com")

        XCTAssertNil(resolved)
    }

    // MARK: - Case Insensitivity

    func testResolutionIsCaseInsensitive() {
        let policy = PinningPolicy(pins: [Pin(type: .spki, hash: "hash")])
        let set = PolicySet(policies: [
            HostPolicy(pattern: .exact("api.example.com"), policy: policy)
        ])

        let resolver = PolicyResolver(policySet: set)

        XCTAssertNotNil(resolver.resolve(host: "API.EXAMPLE.COM"))
        XCTAssertNotNil(resolver.resolve(host: "Api.Example.Com"))
        XCTAssertNotNil(resolver.resolve(host: "api.example.com"))
    }

    // MARK: - Multiple Matches

    func testMultipleWildcardsSelectMostSpecific() {
        let comPolicy = PinningPolicy(pins: [Pin(type: .spki, hash: "com")])
        let examplePolicy = PinningPolicy(pins: [Pin(type: .spki, hash: "example")])
        let apiPolicy = PinningPolicy(pins: [Pin(type: .spki, hash: "api")])

        let set = PolicySet(policies: [
            HostPolicy(pattern: .wildcard("com"), policy: comPolicy),
            HostPolicy(pattern: .wildcard("example.com"), policy: examplePolicy),
            HostPolicy(pattern: .wildcard("api.example.com"), policy: apiPolicy)
        ])

        let resolver = PolicyResolver(policySet: set)
        let resolved = resolver.resolve(host: "v1.api.example.com")

        XCTAssertEqual(resolved?.pins.first?.hash, "api")
    }
}
