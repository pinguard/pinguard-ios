//
//  PolicyResolverTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 4.02.2026.
//

@testable import PinGuard
import Testing

@Suite
struct PolicyResolverTests {

    private func policy(_ hash: String) -> PinningPolicy {
        PinningPolicy(pins: [Pin(type: .spki, hash: hash)])
    }

    @Test
    func exactMatchWinsOverWildcardRegardlessOfOrder() {
        let orderings: [[HostPolicy]] = [
            [HostPolicy(pattern: .wildcard("example.com"), policy: policy("wildcard")),
             HostPolicy(pattern: .exact("api.example.com"), policy: policy("exact"))],
            [HostPolicy(pattern: .exact("api.example.com"), policy: policy("exact")),
             HostPolicy(pattern: .wildcard("example.com"), policy: policy("wildcard"))]
        ]
        for policies in orderings {
            let resolver = PolicyResolver(policySet: PolicySet(policies: policies))
            #expect(resolver.resolve(host: "api.example.com")?.pins.first?.hash == "exact")
        }
    }

    @Test
    func mostSpecificWildcardWins() {
        let set = PolicySet(policies: [
            HostPolicy(pattern: .wildcard("com"), policy: policy("com")),
            HostPolicy(pattern: .wildcard("example.com"), policy: policy("example")),
            HostPolicy(pattern: .wildcard("api.example.com"), policy: policy("api"))
        ])
        let resolver = PolicyResolver(policySet: set)
        #expect(resolver.resolve(host: "v1.api.example.com")?.pins.first?.hash == "api")
        #expect(resolver.resolve(host: "api.example.com")?.pins.first?.hash == "example")
    }

    @Test
    func fallsBackToDefaultPolicy() {
        let set = PolicySet(policies: [HostPolicy(pattern: .exact("example.com"), policy: policy("specific"))],
                            defaultPolicy: policy("default"))
        let resolver = PolicyResolver(policySet: set)
        #expect(resolver.resolve(host: "other.com")?.pins.first?.hash == "default")
    }

    @Test
    func returnsNilWithoutMatchOrDefault() {
        let set = PolicySet(policies: [HostPolicy(pattern: .exact("example.com"), policy: policy("specific"))])
        let resolver = PolicyResolver(policySet: set)
        #expect(resolver.resolve(host: "other.com") == nil)
        #expect(PolicyResolver(policySet: PolicySet(policies: [])).resolve(host: "example.com") == nil)
    }

    @Test
    func emptyHostReturnsNilEvenWithDefault() {
        let resolver = PolicyResolver(policySet: PolicySet(policies: [], defaultPolicy: policy("default")))
        #expect(resolver.resolve(host: "") == nil)
        #expect(resolver.resolve(host: "...") == nil)
    }

    @Test(arguments: ["API.EXAMPLE.COM", "Api.Example.Com", "api.example.com."])
    func resolutionIsCaseAndDotInsensitive(host: String) {
        let set = PolicySet(policies: [HostPolicy(pattern: .exact("api.example.com"), policy: policy("hash"))])
        #expect(PolicyResolver(policySet: set).resolve(host: host) != nil)
    }
}
