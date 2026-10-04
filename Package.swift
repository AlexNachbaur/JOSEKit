// swift-tools-version: 6.0

import PackageDescription

let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6)
]

// CryptoKit ships with Apple's operating systems. Everywhere else the same API comes from
// swift-crypto, which is only built for those platforms.
let nonApplePlatforms: [Platform] = [.linux, .windows, .android, .wasi, .openbsd]
let crypto: Target.Dependency = .product(
    name: "Crypto",
    package: "swift-crypto",
    condition: .when(platforms: nonApplePlatforms)
)

let package = Package(
    name: "jose-jwk",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "JOSEJWK", targets: ["JOSEJWK"])
    ],
    dependencies: [
        // A path dependency until the repositories are published.
        .package(path: "../jose-core"),
        .package(url: "https://github.com/apple/swift-crypto.git", "4.0.0"..<"6.0.0"),
    ],
    targets: [
        .target(
            name: "JOSEJWK",
            dependencies: [
                .product(name: "JOSECore", package: "jose-core"),
                crypto,
            ],
            swiftSettings: swiftSettings
        ),
        // Not a product. Answers the challenge produced by `interop/closed-loop.mjs` so the Node
        // counterpart can check values this package produced. Run through `scripts/interop.sh`.
        .executableTarget(
            name: "jose-jwk-interop",
            dependencies: ["JOSEJWK", .product(name: "JOSECore", package: "jose-core")],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "JOSEJWKTests",
            dependencies: ["JOSEJWK", .product(name: "JOSECore", package: "jose-core"), crypto],
            resources: [.copy("Fixtures")],
            swiftSettings: swiftSettings
        ),
    ]
)
