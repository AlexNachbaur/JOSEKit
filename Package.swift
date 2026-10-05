// swift-tools-version: 6.0

import PackageDescription

let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6)
]

let core: Target.Dependency = .product(name: "JOSECore", package: "jose-core")
let jwk: Target.Dependency = .product(name: "JOSEJWK", package: "jose-jwk")
let jws: Target.Dependency = .product(name: "JOSEJWS", package: "jose-jws")

let package = Package(
    name: "jose-jwt",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "JOSEJWT", targets: ["JOSEJWT"])
    ],
    dependencies: [
        // Path dependencies until the repositories are published.
        .package(path: "../jose-core"),
        .package(path: "../jose-jwk"),
        .package(path: "../jose-jws"),
    ],
    targets: [
        .target(
            name: "JOSEJWT",
            dependencies: [core, jwk, jws],
            swiftSettings: swiftSettings
        ),
        // Not a product. Answers the challenge produced by `interop/closed-loop.mjs` so the Node
        // counterpart can check values this package produced. Run through `scripts/interop.sh`.
        .executableTarget(
            name: "jose-jwt-interop",
            dependencies: ["JOSEJWT", core, jwk, jws],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "JOSEJWTTests",
            dependencies: ["JOSEJWT", core, jwk, jws],
            resources: [.copy("Fixtures")],
            swiftSettings: swiftSettings
        ),
    ]
)
