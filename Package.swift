// swift-tools-version: 6.0

import PackageDescription

let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6)
]

/// The sibling JOSE packages are tagged releases on GitHub. With `JOSE_LOCAL_PACKAGES` set in
/// the environment they are taken from the sibling directories instead, so that all five can be
/// changed together before anything is tagged (`JOSE_LOCAL_PACKAGES=1 swift test`).
func sibling(_ name: String) -> Package.Dependency {
    if Context.environment["JOSE_LOCAL_PACKAGES"] != nil {
        return .package(path: "../\(name)")
    }
    return .package(url: "https://github.com/AlexNachbaur/\(name).git", from: "0.1.0")
}

// CryptoKit ships with Apple's operating systems. Everywhere else the same API comes from
// swift-crypto, which is only built for those platforms.
let nonApplePlatforms: [Platform] = [.linux, .windows, .android, .wasi, .openbsd]
let crypto: Target.Dependency = .product(
    name: "Crypto",
    package: "swift-crypto",
    condition: .when(platforms: nonApplePlatforms)
)

// RSA is not in CryptoKit. On Apple platforms it comes from Security.framework; elsewhere from
// swift-crypto's extras, which are likewise only built for those platforms.
let cryptoExtras: Target.Dependency = .product(
    name: "CryptoExtras",
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
        sibling("jose-core"),
        .package(url: "https://github.com/apple/swift-crypto.git", "4.0.0"..<"6.0.0"),
    ],
    targets: [
        .target(
            name: "JOSEJWK",
            dependencies: [
                .product(name: "JOSECore", package: "jose-core"),
                crypto,
                cryptoExtras,
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
