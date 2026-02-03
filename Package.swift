// swift-tools-version: 6.2
import PackageDescription

let package = Package(
name: "PinGuard",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
        .tvOS(.v13),
        .watchOS(.v6),
        .visionOS(.v1)
    ],
    products: [
        .library(
            name: "PinGuard",
            targets: ["PinGuard"]
        ),
        .library(
            name: "PinGuardTestSupport",
            targets: ["PinGuardTestSupport"]
        )
    ],
    targets: [
        .target(
            name: "PinGuard",
            path: "Sources/PinGuard",
            swiftSettings: [
                .define("PINGUARD_SPM")
            ],
            linkerSettings: [
                .linkedFramework("Security")
            ]
        ),

        .target(
            name: "PinGuardTestSupport",
            dependencies: ["PinGuard"],
            path: "Tests/PinGuardTestSupport"
        ),

        .testTarget(
            name: "PinGuardTests",
            dependencies: [
                "PinGuard",
                "PinGuardTestSupport"
            ],
            path: "Tests/PinGuardTests",
            resources: [
                .process("Fixtures")
            ]
        )
    ]
)
