// swift-tools-version: 6.0

import PackageDescription

let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6)
]

let core: Target.Dependency = .product(name: "JOSECore", package: "jose-core")
let jwk: Target.Dependency = .product(name: "JOSEJWK", package: "jose-jwk")
let jws: Target.Dependency = .product(name: "JOSEJWS", package: "jose-jws")
let jwe: Target.Dependency = .product(name: "JOSEJWE", package: "jose-jwe")

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
        .library(name: "JOSEJWT", targets: ["JOSEJWT"]),
        // Encrypted and nested JWTs. A separate product so that an application that only signs
        // and verifies does not build the encryption code.
        .library(name: "JOSEJWTEncrypted", targets: ["JOSEJWTEncrypted"]),
    ],
    dependencies: [
        // Path dependencies until the repositories are published.
        .package(path: "../jose-core"),
        .package(path: "../jose-jwk"),
        .package(path: "../jose-jws"),
        .package(path: "../jose-jwe"),
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
        .target(
            name: "JOSEJWTEncrypted",
            dependencies: ["JOSEJWT", core, jwk, jws, jwe],
            swiftSettings: swiftSettings
        ),
        .executableTarget(
            name: "jose-jwt-encrypted-interop",
            dependencies: ["JOSEJWT", "JOSEJWTEncrypted", core, jwk, jws, jwe],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "JOSEJWTEncryptedTests",
            dependencies: ["JOSEJWT", "JOSEJWTEncrypted", core, jwk, jws, jwe],
            resources: [.copy("Fixtures")],
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
