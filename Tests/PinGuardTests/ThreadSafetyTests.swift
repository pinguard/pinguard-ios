//
//  ThreadSafetyTests.swift
//  PinGuard
//
//  Created by PinGuard Refactor on 4.02.2026.
//

import SwiftUI
import XCTest
@testable import PinGuard

final class ThreadSafetyTests: XCTestCase {

    // MARK: - Concurrent Configuration Updates

    @MainActor
    func testConcurrentConfigurationUpdates() async {
        let pinGuard = PinGuard.shared

        let iterations = 100
        let expectation = expectation(description: "All updates complete")
        expectation.expectedFulfillmentCount = iterations

        // Create different configurations
        let configs = (0..<iterations).map { index in
            PinGuard.Configuration(
                environments: [
                    .prod: PinGuard.Configuration.EnvironmentConfiguration(
                        policySet: PolicySet(policies: [
                            HostPolicy(
                                pattern: .exact("example\(index).com"),
                                policy: PinningPolicy(pins: [Pin(type: .spki, hash: "hash\(index)")])
                            )
                        ])
                    )
                ],
                current: .prod
            )
        }

        // Update configuration concurrently from multiple tasks
        Task {
            await withTaskGroup(of: Void.self) { group in
                for config in configs {
                    group.addTask { @Sendable in
                        await pinGuard.update(configuration: config)
                        await MainActor.run {
                            expectation.fulfill()
                        }
                    }
                }
            }
        }

        await fulfillment(of: [expectation], timeout: 5.0)

        // Verify we can still read configuration without crashes
        let finalConfig = await MainActor.run {
            pinGuard.currentConfiguration()
        }

        XCTAssertNotNil(finalConfig)
    }

    @MainActor
    func testConcurrentReadsAndWrites() async {
        let pinGuard = PinGuard.shared

        let readCount = 50
        let writeCount = 50
        let totalOps = readCount + writeCount

        let expectation = expectation(description: "All operations complete")
        expectation.expectedFulfillmentCount = totalOps

        let config = PinGuard.Configuration(
            environments: [
                .prod: PinGuard.Configuration.EnvironmentConfiguration(
                    policySet: PolicySet(policies: [
                        HostPolicy(
                            pattern: .exact("test.com"),
                            policy: PinningPolicy(pins: [Pin(type: .spki, hash: "hash")])
                        )
                    ])
                )
            ],
            current: .prod
        )

        Task {
            await withTaskGroup(of: Void.self) { group in
                // Add read tasks
                for _ in 0..<readCount {
                    group.addTask { @Sendable in
                        let _ = await MainActor.run {
                            pinGuard.currentConfiguration()
                        }
                        await MainActor.run {
                            expectation.fulfill()
                        }
                    }
                }

                // Add write tasks
                for _ in 0..<writeCount {
                    group.addTask { @Sendable in
                        await pinGuard.update(configuration: config)
                        await MainActor.run {
                            expectation.fulfill()
                        }
                    }
                }
            }
        }

        await fulfillment(of: [expectation], timeout: 5.0)

        // Verify final state is valid
        let finalConfig = await MainActor.run {
            pinGuard.currentConfiguration()
        }
        XCTAssertNotNil(finalConfig)
    }

    // MARK: - Concurrent Evaluations

    func testConcurrentTrustEvaluations() async {
        let policy = PinningPolicy(
            pins: [Pin(type: .spki, hash: "testHash")],
            failStrategy: .strict
        )

        let policySet = PolicySet(
            policies: [
                HostPolicy(pattern: .exact("example.com"), policy: policy)
            ]
        )

        let evaluator = TrustEvaluator(policySet: policySet)

        // Wrap non-Sendable values in a local @unchecked Sendable container for test purposes
        struct _UncheckedSendableContext: @unchecked Sendable {
            let evaluator: TrustEvaluator
            let policy: PinningPolicy
            let host: String
            let chain: CertificateChain
        }

        let mockChain = CertificateChain(candidates: [])

        let context = _UncheckedSendableContext(
            evaluator: evaluator,
            policy: policy,
            host: "example.com",
            chain: mockChain
        )

        let iterations = 100
        let expectation = expectation(description: "All evaluations complete")
        expectation.expectedFulfillmentCount = iterations

        Task {
            await withTaskGroup(of: Void.self) { group in
                for _ in 0..<iterations {
                    group.addTask { @Sendable in
                        // Use the unchecked-sendable context so the closure only captures a Sendable value
                        let ctx = context
                        var events: [PinGuardEvent] = []
                        _ = ctx.evaluator.evaluate(
                            chain: ctx.chain,
                            systemTrusted: true,
                            host: ctx.host,
                            policy: ctx.policy,
                            events: &events
                        )
                        await MainActor.run {
                            expectation.fulfill()
                        }
                    }
                }
            }
        }

        await fulfillment(of: [expectation], timeout: 5.0)
    }

    // MARK: - Configuration Builder

    func testBuilderIsNotThreadSafe() {
        // This test documents that Builder is NOT thread-safe by design
        // Builder is meant to be used on a single thread during configuration
        // This is acceptable as configuration is typically done once at startup

        var builder = PinGuard.Builder()
        builder.environment(
            .prod,
            policySet: PolicySet(policies: []),
            mtls: nil
        )

        XCTAssertEqual(builder.environments.count, 1)
    }

    // MARK: - PolicyResolver Thread Safety

    func testPolicyResolverImmutableAndThreadSafe() async {
        // Wrap non-Sendable values in a local @unchecked Sendable container for test purposes
        struct _UncheckedSendableResolverContext: @unchecked Sendable {
            let resolver: PolicyResolver
            let host: String
        }

        let policy = PinningPolicy(pins: [Pin(type: .spki, hash: "hash")])
        let policySet = PolicySet(policies: [
            HostPolicy(pattern: .exact("example.com"), policy: policy)
        ])

        let resolver = PolicyResolver(policySet: policySet)
        let ctx = _UncheckedSendableResolverContext(resolver: resolver, host: "example.com")

        let iterations = 100
        let expectation = expectation(description: "All resolutions complete")
        expectation.expectedFulfillmentCount = iterations

        Task {
            await withTaskGroup(of: Void.self) { group in
                for _ in 0..<iterations {
                    group.addTask { @Sendable in
                        _ = ctx.resolver.resolve(host: ctx.host)
                        await MainActor.run {
                            expectation.fulfill()
                        }
                    }
                }
            }
        }

        await fulfillment(of: [expectation], timeout: 5.0)
    }
}

