// swift-tools-version: 6.0

import PackageDescription

let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6)
]

let core: Target.Dependency = .product(name: "JOSECore", package: "jose-core")
let jwk: Target.Dependency = .product(name: "JOSEJWK", package: "jose-jwk")

// CryptoKit and CommonCrypto ship with Apple's operating systems. Everywhere else AES-GCM and
// AES key wrap come from swift-crypto, and AES-CBC from its extras; neither is built for Apple
// platforms.
let nonApplePlatforms: [Platform] = [.linux, .windows, .android, .wasi, .openbsd]
let crypto: Target.Dependency = .product(
    name: "Crypto",
    package: "swift-crypto",
    condition: .when(platforms: nonApplePlatforms)
)
let cryptoExtras: Target.Dependency = .product(
    name: "CryptoExtras",
    package: "swift-crypto",
    condition: .when(platforms: nonApplePlatforms)
)

let package = Package(
    name: "jose-jwe",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "JOSEJWE", targets: ["JOSEJWE"])
    ],
    dependencies: [
        // Path dependencies until the repositories are published.
        .package(path: "../jose-core"),
        .package(path: "../jose-jwk"),
        .package(url: "https://github.com/apple/swift-crypto.git", "4.0.0"..<"6.0.0"),
    ],
    targets: [
        .target(
            name: "JOSEJWE",
            dependencies: [core, jwk, crypto, cryptoExtras],
            swiftSettings: swiftSettings
        ),
        // Not a product. Answers the challenge produced by `interop/closed-loop.mjs` so the Node
        // counterpart can check values this package produced. Run through `scripts/interop.sh`.
        .executableTarget(
            name: "jose-jwe-interop",
            dependencies: ["JOSEJWE", core, jwk],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "JOSEJWETests",
            dependencies: ["JOSEJWE", core, jwk],
            resources: [.copy("Fixtures")],
            swiftSettings: swiftSettings
        ),
    ]
)
