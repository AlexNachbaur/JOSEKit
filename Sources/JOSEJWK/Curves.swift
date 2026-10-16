import Foundation
import JOSECore

#if canImport(CryptoKit)
    import CryptoKit
#else
    import Crypto
#endif

/// An elliptic curve usable in an `EC` JWK. A marker type: keys carry it as a generic parameter
/// so that a P-384 key cannot be passed where a P-256 key is required.
public protocol EllipticCurve: Sendable {
    /// The JWK `crv` value, such as `"P-256"`.
    static var name: String { get }
    /// The size in bytes of one coordinate, and of the private scalar.
    static var coordinateByteCount: Int { get }

    /// Whether `x963` (already checked to be `0x04 || x || y` of the right length) is a point on
    /// the curve.
    static func isPointOnCurve(x963: Data) -> Bool
    /// The uncompressed public point for a private scalar, or `nil` if the scalar is not a valid
    /// private key.
    static func publicKeyX963(privateScalar: Data) -> Data?
    static func generatePrivateScalar() -> Data
}

/// A curve with an ECDSA signature algorithm. Each JOSE curve has exactly one (RFC 7518 §3.4).
public protocol ECDSACurve: EllipticCurve {
    associatedtype Algorithm: ECDSASignatureAlgorithm
    associatedtype SigningKey: Sendable
    associatedtype VerifyingKey: Sendable

    static func signingKey(privateScalar: Data) throws -> SigningKey
    static func verifyingKey(x963: Data) throws -> VerifyingKey
    static func x963(of key: VerifyingKey) -> Data
    static func privateScalar(of key: SigningKey) -> Data
    /// Signs `message`, hashing it as the algorithm specifies, and returns `r || s`.
    static func rawSignature(for message: Data, using key: SigningKey) throws -> Data
    static func isValid(rawSignature: Data, for message: Data, using key: VerifyingKey) -> Bool
}

// The curve types are named with a `Curve` suffix because CryptoKit already has `P256`, `P384`
// and `P521`, and anyone using the Secure Enclave imports both modules.

/// NIST P-256 (secp256r1).
public struct P256Curve: ECDSACurve {
    public typealias Algorithm = ES256
    public static let name = "P-256"
    public static let coordinateByteCount = 32

    public static func isPointOnCurve(x963: Data) -> Bool {
        do {
            _ = try P256.Signing.PublicKey(x963Representation: x963)
            return true
        } catch {
            // CryptoKit's only failure for a correctly sized buffer is a point off the curve.
            return false
        }
    }

    public static func publicKeyX963(privateScalar: Data) -> Data? {
        do {
            return try P256.Signing.PrivateKey(rawRepresentation: privateScalar).publicKey.x963Representation
        } catch {
            return nil
        }
    }

    public static func generatePrivateScalar() -> Data {
        P256.Signing.PrivateKey().rawRepresentation
    }

    public static func signingKey(privateScalar: Data) throws -> P256.Signing.PrivateKey {
        try P256.Signing.PrivateKey(rawRepresentation: privateScalar)
    }

    public static func verifyingKey(x963: Data) throws -> P256.Signing.PublicKey {
        try P256.Signing.PublicKey(x963Representation: x963)
    }

    public static func x963(of key: P256.Signing.PublicKey) -> Data {
        key.x963Representation
    }

    public static func privateScalar(of key: P256.Signing.PrivateKey) -> Data {
        key.rawRepresentation
    }

    public static func rawSignature(for message: Data, using key: P256.Signing.PrivateKey) throws -> Data {
        try key.signature(for: message).rawRepresentation
    }

    public static func isValid(rawSignature: Data, for message: Data, using key: P256.Signing.PublicKey) -> Bool {
        do {
            return key.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: rawSignature), for: message)
        } catch {
            // The bytes are not a P-256 signature at all, so they are not a valid one.
            return false
        }
    }
}

/// NIST P-384 (secp384r1).
public struct P384Curve: ECDSACurve {
    public typealias Algorithm = ES384
    public static let name = "P-384"
    public static let coordinateByteCount = 48

    public static func isPointOnCurve(x963: Data) -> Bool {
        do {
            _ = try P384.Signing.PublicKey(x963Representation: x963)
            return true
        } catch {
            return false
        }
    }

    public static func publicKeyX963(privateScalar: Data) -> Data? {
        do {
            return try P384.Signing.PrivateKey(rawRepresentation: privateScalar).publicKey.x963Representation
        } catch {
            return nil
        }
    }

    public static func generatePrivateScalar() -> Data {
        P384.Signing.PrivateKey().rawRepresentation
    }

    public static func signingKey(privateScalar: Data) throws -> P384.Signing.PrivateKey {
        try P384.Signing.PrivateKey(rawRepresentation: privateScalar)
    }

    public static func verifyingKey(x963: Data) throws -> P384.Signing.PublicKey {
        try P384.Signing.PublicKey(x963Representation: x963)
    }

    public static func x963(of key: P384.Signing.PublicKey) -> Data {
        key.x963Representation
    }

    public static func privateScalar(of key: P384.Signing.PrivateKey) -> Data {
        key.rawRepresentation
    }

    public static func rawSignature(for message: Data, using key: P384.Signing.PrivateKey) throws -> Data {
        try key.signature(for: message).rawRepresentation
    }

    public static func isValid(rawSignature: Data, for message: Data, using key: P384.Signing.PublicKey) -> Bool {
        do {
            return key.isValidSignature(try P384.Signing.ECDSASignature(rawRepresentation: rawSignature), for: message)
        } catch {
            return false
        }
    }
}

/// NIST P-521 (secp521r1). Note 521, not 512.
public struct P521Curve: ECDSACurve {
    public typealias Algorithm = ES512
    public static let name = "P-521"
    public static let coordinateByteCount = 66

    public static func isPointOnCurve(x963: Data) -> Bool {
        do {
            _ = try P521.Signing.PublicKey(x963Representation: x963)
            return true
        } catch {
            return false
        }
    }

    public static func publicKeyX963(privateScalar: Data) -> Data? {
        do {
            return try P521.Signing.PrivateKey(rawRepresentation: privateScalar).publicKey.x963Representation
        } catch {
            return nil
        }
    }

    public static func generatePrivateScalar() -> Data {
        P521.Signing.PrivateKey().rawRepresentation
    }

    public static func signingKey(privateScalar: Data) throws -> P521.Signing.PrivateKey {
        try P521.Signing.PrivateKey(rawRepresentation: privateScalar)
    }

    public static func verifyingKey(x963: Data) throws -> P521.Signing.PublicKey {
        try P521.Signing.PublicKey(x963Representation: x963)
    }

    public static func x963(of key: P521.Signing.PublicKey) -> Data {
        key.x963Representation
    }

    public static func privateScalar(of key: P521.Signing.PrivateKey) -> Data {
        key.rawRepresentation
    }

    public static func rawSignature(for message: Data, using key: P521.Signing.PrivateKey) throws -> Data {
        try key.signature(for: message).rawRepresentation
    }

    public static func isValid(rawSignature: Data, for message: Data, using key: P521.Signing.PublicKey) -> Bool {
        do {
            return key.isValidSignature(try P521.Signing.ECDSASignature(rawRepresentation: rawSignature), for: message)
        } catch {
            return false
        }
    }
}
