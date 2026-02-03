// swift-tools-version: 6.2
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
        ),
        .library(
            name: "PinGuardTestSupport",
            targets: ["PinGuardTestSupport"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/realm/SwiftLint.git", from: "0.55.0")
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
            ],
            plugins: [
              .plugin(name: "SwiftLintBuildToolPlugin", package: "SwiftLint")
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
            path: "Tests/PinGuardTests"
        )
    ]
)
