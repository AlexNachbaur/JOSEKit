// swift-tools-version: 6.0

import PackageDescription

let swiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6)
]

// CryptoKit and CommonCrypto ship with Apple's operating systems. Everywhere else the same APIs
// come from swift-crypto, and RSA, AES-CBC and PBKDF2 from its extras (on Apple platforms those
// come from Security.framework and CommonCrypto). Neither product is built for Apple platforms.
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
    name: "JOSEKit",
    // The lowest runtimes that support constrained existentials (`any Signer<ES256>`), which the
    // signing protocols are designed to be used through.
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
        .visionOS(.v1),
    ],
    // One library per module, so that an application builds only what it uses.
    products: [
        .library(name: "JOSECore", targets: ["JOSECore"]),
        .library(name: "JOSEJWK", targets: ["JOSEJWK"]),
        .library(name: "JOSEJWS", targets: ["JOSEJWS"]),
        .library(name: "JOSEJWE", targets: ["JOSEJWE"]),
        .library(name: "JOSEJWT", targets: ["JOSEJWT"]),
        // Encrypted and nested JWTs. Separate from JOSEJWT so that an application that only signs
        // and verifies does not build the encryption code.
        .library(name: "JOSEJWTEncrypted", targets: ["JOSEJWTEncrypted"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "4.0.0"..<"6.0.0")
    ],
    targets: [
        // MARK: Libraries

        .target(
            name: "JOSECore",
            swiftSettings: swiftSettings
        ),
        .target(
            name: "JOSEJWK",
            dependencies: ["JOSECore", crypto, cryptoExtras],
            swiftSettings: swiftSettings
        ),
        .target(
            name: "JOSEJWS",
            dependencies: ["JOSECore", "JOSEJWK", crypto],
            swiftSettings: swiftSettings
        ),
        .target(
            name: "JOSEJWE",
            dependencies: ["JOSECore", "JOSEJWK", "CZlib", crypto, cryptoExtras],
            swiftSettings: swiftSettings
        ),
        // The system zlib, for JWE compression (`zip`), on every platform. No pkg-config lookup:
        // on a Mac it can pick up a Homebrew zlib in place of the SDK's, which breaks builds for
        // other Apple platforms.
        .systemLibrary(
            name: "CZlib",
            providers: [.apt(["zlib1g-dev"]), .yum(["zlib-devel"])]
        ),
        .target(
            name: "JOSEJWT",
            dependencies: ["JOSECore", "JOSEJWK", "JOSEJWS"],
            swiftSettings: swiftSettings
        ),
        .target(
            name: "JOSEJWTEncrypted",
            dependencies: ["JOSECore", "JOSEJWK", "JOSEJWS", "JOSEJWE", "JOSEJWT"],
            swiftSettings: swiftSettings
        ),

        // MARK: Interoperability executables
        // Not products. Each answers the challenge produced by its module's closed-loop script in
        // `interop/`, so that the Node counterpart can check what the module produced. Run them
        // through `scripts/interop.sh`.

        .executableTarget(
            name: "jose-core-interop",
            dependencies: ["JOSECore"],
            swiftSettings: swiftSettings
        ),
        .executableTarget(
            name: "jose-jwk-interop",
            dependencies: ["JOSECore", "JOSEJWK"],
            swiftSettings: swiftSettings
        ),
        .executableTarget(
            name: "jose-jws-interop",
            dependencies: ["JOSECore", "JOSEJWK", "JOSEJWS"],
            swiftSettings: swiftSettings
        ),
        .executableTarget(
            name: "jose-jwe-interop",
            dependencies: ["JOSECore", "JOSEJWK", "JOSEJWE"],
            swiftSettings: swiftSettings
        ),
        .executableTarget(
            name: "jose-jwt-interop",
            dependencies: ["JOSECore", "JOSEJWK", "JOSEJWS", "JOSEJWT"],
            swiftSettings: swiftSettings
        ),
        .executableTarget(
            name: "jose-jwt-encrypted-interop",
            dependencies: ["JOSECore", "JOSEJWK", "JOSEJWS", "JOSEJWE", "JOSEJWT", "JOSEJWTEncrypted"],
            swiftSettings: swiftSettings
        ),

        // MARK: Tests

        .testTarget(
            name: "JOSECoreTests",
            dependencies: ["JOSECore"],
            resources: [.copy("Fixtures")],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "JOSEJWKTests",
            dependencies: ["JOSECore", "JOSEJWK", crypto],
            resources: [.copy("Fixtures")],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "JOSEJWSTests",
            dependencies: ["JOSECore", "JOSEJWK", "JOSEJWS"],
            resources: [.copy("Fixtures")],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "JOSEJWETests",
            dependencies: ["JOSECore", "JOSEJWK", "JOSEJWE"],
            resources: [.copy("Fixtures")],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "JOSEJWTTests",
            dependencies: ["JOSECore", "JOSEJWK", "JOSEJWS", "JOSEJWT"],
            resources: [.copy("Fixtures")],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "JOSEJWTEncryptedTests",
            dependencies: ["JOSECore", "JOSEJWK", "JOSEJWS", "JOSEJWE", "JOSEJWT", "JOSEJWTEncrypted"],
            resources: [.copy("Fixtures")],
            swiftSettings: swiftSettings
        ),
        // The published examples of RFC 7520, RFC 7797 and RFC 8037, across every module.
        .testTarget(
            name: "RFCVectorTests",
            dependencies: ["JOSECore", "JOSEJWK", "JOSEJWS", "JOSEJWE", "JOSEJWT", "JOSEJWTEncrypted"],
            resources: [.copy("Fixtures")],
            swiftSettings: swiftSettings
        ),
    ]
)
