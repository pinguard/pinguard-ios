//
//  HostMatcherTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 4.02.2026.
//

@testable import PinGuard
import Testing

@Suite
struct HostMatcherTests {

    @Test(arguments: ["api.example.com", "API.EXAMPLE.COM", "api.example.com.", ".api.example.com"])
    func exactPatternMatchesNormalizedForms(host: String) {
        #expect(HostMatcher.matches(.exact("api.example.com"), host: host))
    }

    @Test(arguments: ["www.example.com", "example.com", "sub.api.example.com", ""])
    func exactPatternRejectsOtherHosts(host: String) {
        #expect(!HostMatcher.matches(.exact("api.example.com"), host: host))
    }

    @Test(arguments: ["api.example.com", "www.example.com", "a.example.com", "Api.Example.Com"])
    func wildcardMatchesSingleLabel(host: String) {
        #expect(HostMatcher.matches(.wildcard("example.com"), host: host))
    }

    @Test(arguments: ["example.com", "a.b.example.com", "x.y.z.example.com", "", "com"])
    func wildcardRejectsBaseAndDeeperHosts(host: String) {
        #expect(!HostMatcher.matches(.wildcard("example.com"), host: host))
    }

    @Test
    func singleLabelHostMatchesExactly() {
        #expect(HostMatcher.matches(.exact("localhost"), host: "LOCALHOST"))
    }
}
