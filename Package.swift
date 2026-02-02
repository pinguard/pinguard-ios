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
            name: "PinGuard-Dynamic",
            type: .dynamic,
            targets: ["PinGuard"]
        ),

        .library(
            name: "PinGuardTestSupport",
            targets: ["PinGuardTestSupport"]
        )
    ],
    dependencies: [
        // - TODO: Add swift crypto if necessary
    ],
    targets: [
        .target(
            name: "PinGuard",
            path: "Sources/PinGuard",
            exclude: [
                // - TODO: Exclude unnecessary files here
            ],
            swiftSettings: [
                .define("PINGUARD_SPM")
            ],
            linkerSettings: [
                .linkedFramework("Security")
            ]
        ),
        .testTarget(
            name: "PinGuardTests",
            dependencies: ["PinGuard", "PinGuardTestSupport"],
            path: "Tests/PinGuardTests",
            resources: [
                .process("Fixtures")
            ]
        )
    ]
)
