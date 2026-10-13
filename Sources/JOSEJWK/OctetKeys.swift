import Foundation
import JOSECore

#if canImport(CryptoKit)
    import CryptoKit
#else
    import Crypto
#endif

/// An Ed25519 public key (RFC 8037: `kty` `OKP`, `crv` `Ed25519`).
public struct Ed25519PublicKey: Sendable, Hashable {
    public static let curveName = "Ed25519"
    public static let byteCount = 32

    /// The 32-byte public key, the JWK `x` member.
    public let rawRepresentation: Data

    public init(rawRepresentation: Data) throws(JWKError) {
        guard rawRepresentation.count == Self.byteCount else {
            throw .wrongByteCount(
                member: "x",
                curve: Self.curveName,
                expected: Self.byteCount,
                found: rawRepresentation.count
            )
        }
        self.rawRepresentation = Data(rawRepresentation)
    }

    /// Wraps a CryptoKit (or swift-crypto) key.
    public init(_ key: Curve25519.Signing.PublicKey) throws(JWKError) {
        try self.init(rawRepresentation: key.rawRepresentation)
    }
}

/// An Ed25519 private key held in memory. Not `Codable` or `Equatable`, and its description is
/// redacted; see ``ECPrivateKey``.
public struct Ed25519PrivateKey: Sendable {
    /// The 32-byte seed, the JWK `d` member.
    public let rawRepresentation: Data
    public let publicKey: Ed25519PublicKey

    /// Generates a new key.
    public init() throws(JWKError) {
        try self.init(rawRepresentation: Curve25519.Signing.PrivateKey().rawRepresentation)
    }

    public init(rawRepresentation: Data) throws(JWKError) {
        guard rawRepresentation.count == Ed25519PublicKey.byteCount else {
            throw .wrongByteCount(
                member: "d",
                curve: Ed25519PublicKey.curveName,
                expected: Ed25519PublicKey.byteCount,
                found: rawRepresentation.count
            )
        }
        let seed = Data(rawRepresentation)
        let key: Curve25519.Signing.PrivateKey
        do {
            key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        } catch {
            throw .invalidPrivateKey(curve: Ed25519PublicKey.curveName)
        }
        self.rawRepresentation = seed
        self.publicKey = try Ed25519PublicKey(rawRepresentation: key.publicKey.rawRepresentation)
    }
}

extension Ed25519PrivateKey: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String {
        "Ed25519PrivateKey(redacted)"
    }

    public var debugDescription: String {
        description
    }
}

/// A symmetric key (`kty` `oct`), as used for HMAC.
///
/// Not `Codable`, `Equatable` or `Hashable`, and its description is redacted. There is
/// deliberately no way to place one in a ``JWK`` or ``JWKSet``, which hold public keys only.
public struct SymmetricKeyMaterial: Sendable {
    public let rawRepresentation: Data

    public init(rawRepresentation: Data) {
        self.rawRepresentation = Data(rawRepresentation)
    }

    /// Generates a random key of `byteCount` bytes. A count of zero or less gives an empty key,
    /// which every use of this type then refuses as too short.
    public init(randomByteCount byteCount: Int) {
        guard byteCount > 0 else {
            rawRepresentation = Data()
            return
        }
        rawRepresentation = SymmetricKey(size: SymmetricKeySize(bitCount: byteCount * 8))
            .withUnsafeBytes { Data($0) }
    }
}

extension SymmetricKeyMaterial: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String {
        "SymmetricKeyMaterial(\(rawRepresentation.count) bytes, redacted)"
    }

    public var debugDescription: String {
        description
    }
}
