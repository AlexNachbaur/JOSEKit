// swift-tools-version: 6.0

import PackageDescription

let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6)
]

let package = Package(
    name: "jose-core",
    // The lowest runtimes that support constrained existentials (`any Signer<ES256>`), which the
    // signing protocols are designed to be used through.
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "JOSECore", targets: ["JOSECore"])
    ],
    targets: [
        .target(
            name: "JOSECore",
            swiftSettings: swiftSettings
        ),
        // Not a product. Answers the challenge produced by `interop/closed-loop.mjs` so the Node
        // counterpart can check values this package produced. Run through `scripts/interop.sh`.
        .executableTarget(
            name: "jose-core-interop",
            dependencies: ["JOSECore"],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "JOSECoreTests",
            dependencies: ["JOSECore"],
            resources: [.copy("Fixtures")],
            swiftSettings: swiftSettings
        ),
    ]
)
