// swift-tools-version: 6.0

import PackageDescription

let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6)
]

let core: Target.Dependency = .product(name: "JOSECore", package: "jose-core")
let jwk: Target.Dependency = .product(name: "JOSEJWK", package: "jose-jwk")

let package = Package(
    name: "jose-jws",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "JOSEJWS", targets: ["JOSEJWS"])
    ],
    dependencies: [
        // Path dependencies until the repositories are published.
        .package(path: "../jose-core"),
        .package(path: "../jose-jwk"),
    ],
    targets: [
        .target(
            name: "JOSEJWS",
            dependencies: [core, jwk],
            swiftSettings: swiftSettings
        ),
        // Not a product. Answers the challenge produced by `interop/closed-loop.mjs` so the Node
        // counterpart can check values this package produced. Run through `scripts/interop.sh`.
        .executableTarget(
            name: "jose-jws-interop",
            dependencies: ["JOSEJWS", core, jwk],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "JOSEJWSTests",
            dependencies: ["JOSEJWS", core, jwk],
            resources: [.copy("Fixtures")],
            swiftSettings: swiftSettings
        ),
    ]
)
