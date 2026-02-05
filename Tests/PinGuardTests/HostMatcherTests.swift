//
//  HostMatcherTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 4.02.2026.
//

import XCTest
@testable import PinGuard

final class HostMatcherTests: XCTestCase {

    // MARK: - Exact Matching

    func testExactMatchSuccess() {
        let pattern = HostPattern.exact("api.example.com")
        XCTAssertTrue(HostMatcher.matches(pattern, host: "api.example.com"))
        XCTAssertTrue(HostMatcher.matches(pattern, host: "API.EXAMPLE.COM"))
    }

    func testExactMatchFailure() {
        let pattern = HostPattern.exact("api.example.com")
        XCTAssertFalse(HostMatcher.matches(pattern, host: "www.example.com"))
        XCTAssertFalse(HostMatcher.matches(pattern, host: "example.com"))
        XCTAssertFalse(HostMatcher.matches(pattern, host: "sub.api.example.com"))
    }

    // MARK: - Wildcard Matching

    func testWildcardMatchesSingleSubdomain() {
        let pattern = HostPattern.wildcard("example.com")
        XCTAssertTrue(HostMatcher.matches(pattern, host: "api.example.com"))
        XCTAssertTrue(HostMatcher.matches(pattern, host: "www.example.com"))
        XCTAssertTrue(HostMatcher.matches(pattern, host: "a.example.com"))
    }

    func testWildcardDoesNotMatchBase() {
        let pattern = HostPattern.wildcard("example.com")
        XCTAssertFalse(HostMatcher.matches(pattern, host: "example.com"))
    }

    func testWildcardDoesNotMatchMultipleLevels() {
        let pattern = HostPattern.wildcard("example.com")
        XCTAssertFalse(HostMatcher.matches(pattern, host: "a.b.example.com"))
        XCTAssertFalse(HostMatcher.matches(pattern, host: "x.y.z.example.com"))
    }

    func testWildcardMatchesCaseInsensitive() {
        let pattern = HostPattern.wildcard("example.com")
        XCTAssertTrue(HostMatcher.matches(pattern, host: "API.EXAMPLE.COM"))
        XCTAssertTrue(HostMatcher.matches(pattern, host: "Api.Example.Com"))
    }

    // MARK: - Edge Cases

    func testEmptyHostNeverMatches() {
        let exactPattern = HostPattern.exact("example.com")
        let wildcardPattern = HostPattern.wildcard("example.com")

        XCTAssertFalse(HostMatcher.matches(exactPattern, host: ""))
        XCTAssertFalse(HostMatcher.matches(wildcardPattern, host: ""))
    }

    func testSingleLabelHostExactMatch() {
        let pattern = HostPattern.exact("localhost")
        XCTAssertTrue(HostMatcher.matches(pattern, host: "localhost"))
        XCTAssertTrue(HostMatcher.matches(pattern, host: "LOCALHOST"))
    }

    func testHostWithTrailingDot() {
        let pattern = HostPattern.exact("example.com")
        XCTAssertTrue(HostMatcher.matches(pattern, host: "example.com."))
    }

    func testHostWithLeadingDot() {
        let pattern = HostPattern.exact("example.com")
        XCTAssertTrue(HostMatcher.matches(pattern, host: ".example.com"))
    }

    func testMultipleDotsAreNormalized() {
        let pattern = HostPattern.exact("example.com")
        XCTAssertTrue(HostMatcher.matches(pattern, host: "example.com.."))
    }

    // MARK: - Pattern Parsing

    func testParseExactPattern() {
        let pattern = HostPattern.parse("example.com")
        XCTAssertEqual(pattern, HostPattern.exact("example.com"))
    }

    func testParseWildcardPattern() {
        let pattern = HostPattern.parse("*.example.com")
        XCTAssertEqual(pattern, HostPattern.wildcard("example.com"))
    }

    func testParseNormalizesCase() {
        let pattern = HostPattern.parse("EXAMPLE.COM")
        XCTAssertEqual(pattern, HostPattern.exact("example.com"))
    }

    func testParseTrimsTrailingDot() {
        let pattern = HostPattern.parse("example.com.")
        XCTAssertEqual(pattern, HostPattern.exact("example.com"))
    }

    func testParseWildcardTrimsTrailingDot() {
        let pattern = HostPattern.parse("*.example.com.")
        XCTAssertEqual(pattern, HostPattern.wildcard("example.com"))
    }

    // MARK: - Raw Value

    func testExactPatternRawValue() {
        let pattern = HostPattern.exact("example.com")
        XCTAssertEqual(pattern.rawValue, "example.com")
    }

    func testWildcardPatternRawValue() {
        let pattern = HostPattern.wildcard("example.com")
        XCTAssertEqual(pattern.rawValue, "*.example.com")
    }
}
