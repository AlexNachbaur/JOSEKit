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

let core: Target.Dependency = .product(name: "JOSECore", package: "jose-core")
let jwk: Target.Dependency = .product(name: "JOSEJWK", package: "jose-jwk")

// Only hashing is needed here (certificate thumbprints). CryptoKit on Apple platforms,
// swift-crypto elsewhere.
let nonApplePlatforms: [Platform] = [.linux, .windows, .android, .wasi, .openbsd]
let crypto: Target.Dependency = .product(
    name: "Crypto",
    package: "swift-crypto",
    condition: .when(platforms: nonApplePlatforms)
)

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
        sibling("jose-core"),
        sibling("jose-jwk"),
        .package(url: "https://github.com/apple/swift-crypto.git", "4.0.0"..<"6.0.0"),
    ],
    targets: [
        .target(
            name: "JOSEJWS",
            dependencies: [core, jwk, crypto],
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
