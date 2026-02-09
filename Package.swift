// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PinGuard",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .tvOS(.v15),
        .watchOS(.v8),
        .visionOS(.v1)
    ],
    products: [
        .library(
            name: "PinGuard",
            targets: ["PinGuard"]
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
        .testTarget(
            name: "PinGuardTests",
            dependencies: [
                "PinGuard"
            ],
            path: "Tests/PinGuardTests"
        )
    ]
)
