import Foundation
import JOSECore

#if canImport(CryptoKit)
    import CryptoKit
#else
    import Crypto
#endif

/// A curve usable for ECDH key agreement (RFC 7518 §4.6).
public protocol KeyAgreementCurve: EllipticCurve {
    /// The raw shared secret `Z`: the x-coordinate of the shared point, the full size of the curve.
    static func sharedSecret(privateScalar: Data, publicKeyX963: Data) throws -> Data
}

extension P256Curve: KeyAgreementCurve {
    public static func sharedSecret(privateScalar: Data, publicKeyX963: Data) throws -> Data {
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateScalar)
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: publicKeyX963)
        return try privateKey.sharedSecretFromKeyAgreement(with: publicKey).withUnsafeBytes { Data($0) }
    }
}

extension P384Curve: KeyAgreementCurve {
    public static func sharedSecret(privateScalar: Data, publicKeyX963: Data) throws -> Data {
        let privateKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: privateScalar)
        let publicKey = try P384.KeyAgreement.PublicKey(x963Representation: publicKeyX963)
        return try privateKey.sharedSecretFromKeyAgreement(with: publicKey).withUnsafeBytes { Data($0) }
    }
}

extension P521Curve: KeyAgreementCurve {
    public static func sharedSecret(privateScalar: Data, publicKeyX963: Data) throws -> Data {
        let privateKey = try P521.KeyAgreement.PrivateKey(rawRepresentation: privateScalar)
        let publicKey = try P521.KeyAgreement.PublicKey(x963Representation: publicKeyX963)
        return try privateKey.sharedSecretFromKeyAgreement(with: publicKey).withUnsafeBytes { Data($0) }
    }
}

extension ECPrivateKey where Curve: KeyAgreementCurve {
    /// The ECDH shared secret with another party's public key.
    ///
    /// `ECPublicKey` can only hold a point that is on the curve, so the invalid-curve attack on
    /// ECDH (RFC 7518 §6.2.1 and §4.6.2's validation requirement) is ruled out by the type.
    public func sharedSecret(with publicKey: ECPublicKey<Curve>) throws(JWKError) -> Data {
        do {
            return try Curve.sharedSecret(
                privateScalar: rawRepresentation,
                publicKeyX963: publicKey.x963Representation
            )
        } catch {
            throw .keyAgreementFailed(curve: Curve.name)
        }
    }
}

/// An X25519 public key (RFC 8037: `kty` `OKP`, `crv` `X25519`), used for ECDH key agreement.
public struct X25519PublicKey: Sendable, Hashable {
    public static let curveName = "X25519"
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
}

/// An X25519 private key held in memory. Not `Codable` or `Equatable`, and its description is
/// redacted; see ``ECPrivateKey``.
public struct X25519PrivateKey: Sendable {
    /// The 32-byte private key, the JWK `d` member.
    public let rawRepresentation: Data
    public let publicKey: X25519PublicKey

    /// Generates a new key.
    public init() throws(JWKError) {
        try self.init(rawRepresentation: Curve25519.KeyAgreement.PrivateKey().rawRepresentation)
    }

    public init(rawRepresentation: Data) throws(JWKError) {
        guard rawRepresentation.count == X25519PublicKey.byteCount else {
            throw .wrongByteCount(
                member: "d",
                curve: X25519PublicKey.curveName,
                expected: X25519PublicKey.byteCount,
                found: rawRepresentation.count
            )
        }
        let scalar = Data(rawRepresentation)
        let key: Curve25519.KeyAgreement.PrivateKey
        do {
            key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: scalar)
        } catch {
            throw .invalidPrivateKey(curve: X25519PublicKey.curveName)
        }
        self.rawRepresentation = scalar
        self.publicKey = try X25519PublicKey(rawRepresentation: key.publicKey.rawRepresentation)
    }

    /// The X25519 shared secret with another party's public key.
    ///
    /// Fails when the result is all zeros, which happens for a small set of public keys an
    /// attacker can choose; RFC 7748 §6.1 requires that case to be rejected.
    ///
    /// CryptoKit and swift-crypto both refuse such a key themselves, so the explicit check below
    /// has not been seen to fire. It stays because the requirement is this package's to meet,
    /// not something to leave to an undocumented property of the library underneath.
    public func sharedSecret(with publicKey: X25519PublicKey) throws(JWKError) -> Data {
        do {
            let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation)
            let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey.rawRepresentation)
            let secret = try privateKey.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
            guard secret.contains(where: { $0 != 0 }) else {
                throw JWKError.keyAgreementFailed(curve: X25519PublicKey.curveName)
            }
            return secret
        } catch {
            throw .keyAgreementFailed(curve: X25519PublicKey.curveName)
        }
    }
}

extension X25519PrivateKey: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String {
        "X25519PrivateKey(redacted)"
    }

    public var debugDescription: String {
        description
    }
}
