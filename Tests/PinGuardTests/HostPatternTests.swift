//
//  HostPatternTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import Foundation
@testable import PinGuard
import Testing

@Suite
struct HostPatternTests {

    @Test(arguments: [
        ("example.com", HostPattern.exact("example.com")),
        ("EXAMPLE.COM", HostPattern.exact("example.com")),
        ("example.com.", HostPattern.exact("example.com")),
        ("*.example.com", HostPattern.wildcard("example.com")),
        ("*.example.com.", HostPattern.wildcard("example.com"))
    ])
    func parseProducesExpectedPattern(input: String, expected: HostPattern) {
        #expect(HostPattern.parse(input) == expected)
    }

    @Test
    func rawValueRoundTripsThroughParse() {
        let patterns: [HostPattern] = [.exact("example.com"), .wildcard("example.com")]
        for pattern in patterns {
            #expect(HostPattern.parse(pattern.rawValue) == pattern)
        }
    }

    @Test
    func encodesAsSingleString() throws {
        let data = try JSONEncoder().encode([HostPattern.wildcard("example.com"), .exact("api.example.com")])
        #expect(String(data: data, encoding: .utf8) == #"["*.example.com","api.example.com"]"#)
    }

    @Test
    func decodesFromSingleString() throws {
        let data = Data(#"["*.example.com","api.example.com"]"#.utf8)
        let decoded = try JSONDecoder().decode([HostPattern].self, from: data)
        #expect(decoded == [.wildcard("example.com"), .exact("api.example.com")])
    }
}
