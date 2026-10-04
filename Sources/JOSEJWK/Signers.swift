import Foundation
import JOSECore

#if canImport(CryptoKit)
    import CryptoKit
#else
    import Crypto
#endif

// MARK: - ECDSA

/// Signs with an in-memory ECDSA key. The algorithm follows from the curve.
public struct ECDSASigner<Curve: ECDSACurve>: Signer {
    public typealias Algorithm = Curve.Algorithm

    public let keyID: KeyID?
    public let publicKey: ECPublicKey<Curve>
    private let key: Curve.SigningKey

    public init(privateKey: ECPrivateKey<Curve>, keyID: KeyID? = nil) throws(JWKError) {
        do {
            key = try Curve.signingKey(privateScalar: privateKey.rawRepresentation)
        } catch {
            throw .invalidPrivateKey(curve: Curve.name)
        }
        publicKey = privateKey.publicKey
        self.keyID = keyID
    }

    public func sign(_ message: Data) async throws(SigningError) -> Signature<Algorithm> {
        let raw: Data
        do {
            raw = try Curve.rawSignature(for: message, using: key)
        } catch {
            throw .keyOperationFailed(algorithm: Algorithm.identifier, underlying: error)
        }
        do {
            return try Signature(rawRepresentation: raw)
        } catch {
            throw .invalidSignature(error)
        }
    }
}

/// Verifies ECDSA signatures with a public key. The algorithm follows from the curve.
public struct ECDSAVerifier<Curve: ECDSACurve>: Verifier {
    public typealias Algorithm = Curve.Algorithm

    public let keyID: KeyID?
    private let key: Curve.VerifyingKey

    public init(publicKey: ECPublicKey<Curve>, keyID: KeyID? = nil) throws(JWKError) {
        do {
            key = try Curve.verifyingKey(x963: publicKey.x963Representation)
        } catch {
            throw .pointNotOnCurve(curve: Curve.name)
        }
        self.keyID = keyID
    }

    /// Builds a verifier from a JWK, honouring its `use`, `key_ops` and `alg` restrictions.
    public init(jwk: JWK) throws(JWKError) {
        try jwk.metadata.requirePermission(for: .verify, use: .signature, algorithm: Algorithm.identifier)
        var publicKey: ECPublicKey<Curve>?
        switch jwk.key {
        case .p256(let key):
            publicKey = key as? ECPublicKey<Curve>
        case .p384(let key):
            publicKey = key as? ECPublicKey<Curve>
        case .p521(let key):
            publicKey = key as? ECPublicKey<Curve>
        case .ed25519, .unrecognized:
            publicKey = nil
        }
        guard let publicKey else {
            throw .keyTypeMismatch(expected: "EC \(Curve.name)", found: jwk.keyDescription)
        }
        try self.init(publicKey: publicKey, keyID: jwk.keyID)
    }

    public func verify(_ signature: Signature<Algorithm>, for message: Data) throws(VerificationError) {
        guard Curve.isValid(rawSignature: signature.rawRepresentation, for: message, using: key) else {
            throw .signatureMismatch(algorithm: Algorithm.identifier)
        }
    }
}

extension JWK {
    /// The key type and curve, for error messages.
    var keyDescription: String {
        switch key {
        case .p256:
            return "EC \(P256Curve.name)"
        case .p384:
            return "EC \(P384Curve.name)"
        case .p521:
            return "EC \(P521Curve.name)"
        case .ed25519:
            return "OKP \(Ed25519PublicKey.curveName)"
        case .unrecognized(let unrecognized):
            return unrecognized.keyType
        }
    }
}

// MARK: - Ed25519

/// An algorithm identifier under which Ed25519 keys sign: ``JOSECore/Ed25519`` (RFC 9864) and the
/// older, polymorphic ``JOSECore/EdDSA`` (RFC 8037). The signature scheme is the same; only the
/// `alg` value differs.
public protocol Ed25519KeyAlgorithm: SignatureAlgorithm {}

extension JOSECore.Ed25519: Ed25519KeyAlgorithm {}
extension EdDSA: Ed25519KeyAlgorithm {}

/// Signs with an in-memory Ed25519 key, under either `Ed25519` or `EdDSA`.
public struct Ed25519Signer<Algorithm: Ed25519KeyAlgorithm>: Signer {
    public let keyID: KeyID?
    public let publicKey: Ed25519PublicKey
    private let key: Curve25519.Signing.PrivateKey

    public init(privateKey: Ed25519PrivateKey, keyID: KeyID? = nil) throws(JWKError) {
        do {
            key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey.rawRepresentation)
        } catch {
            throw .invalidPrivateKey(curve: Ed25519PublicKey.curveName)
        }
        publicKey = privateKey.publicKey
        self.keyID = keyID
    }

    public func sign(_ message: Data) async throws(SigningError) -> Signature<Algorithm> {
        let raw: Data
        do {
            raw = try key.signature(for: message)
        } catch {
            throw .keyOperationFailed(algorithm: Algorithm.identifier, underlying: error)
        }
        do {
            return try Signature(rawRepresentation: raw)
        } catch {
            throw .invalidSignature(error)
        }
    }
}

/// Verifies Ed25519 signatures, under either `Ed25519` or `EdDSA`.
public struct Ed25519Verifier<Algorithm: Ed25519KeyAlgorithm>: Verifier {
    public let keyID: KeyID?
    private let key: Curve25519.Signing.PublicKey

    public init(publicKey: Ed25519PublicKey, keyID: KeyID? = nil) throws(JWKError) {
        do {
            key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey.rawRepresentation)
        } catch {
            throw .pointNotOnCurve(curve: Ed25519PublicKey.curveName)
        }
        self.keyID = keyID
    }

    /// Builds a verifier from a JWK, honouring its `use`, `key_ops` and `alg` restrictions.
    public init(jwk: JWK) throws(JWKError) {
        try jwk.metadata.requirePermission(for: .verify, use: .signature, algorithm: Algorithm.identifier)
        guard case .ed25519(let publicKey) = jwk.key else {
            throw .keyTypeMismatch(expected: "OKP \(Ed25519PublicKey.curveName)", found: jwk.keyDescription)
        }
        try self.init(publicKey: publicKey, keyID: jwk.keyID)
    }

    public func verify(_ signature: Signature<Algorithm>, for message: Data) throws(VerificationError) {
        guard key.isValidSignature(signature.rawRepresentation, for: message) else {
            throw .signatureMismatch(algorithm: Algorithm.identifier)
        }
    }
}

// MARK: - HMAC

/// An HMAC algorithm and the hash function it uses.
public protocol HMACAlgorithm: SignatureAlgorithm {
    associatedtype Hash: HashFunction
}

extension HS256: HMACAlgorithm {
    public typealias Hash = SHA256
}

extension HS384: HMACAlgorithm {
    public typealias Hash = SHA384
}

extension HS512: HMACAlgorithm {
    public typealias Hash = SHA512
}

private func hmacKey<Algorithm: HMACAlgorithm>(
    _ key: SymmetricKeyMaterial,
    for algorithm: Algorithm.Type
) throws(JWKError) -> SymmetricKey {
    // RFC 7518 §3.2: "A key of the same size as the hash output ... or larger MUST be used".
    let minimum = Algorithm.Hash.Digest.byteCount
    guard key.rawRepresentation.count >= minimum else {
        throw .keyTooShort(
            algorithm: Algorithm.identifier,
            minimumByteCount: minimum,
            found: key.rawRepresentation.count
        )
    }
    return SymmetricKey(data: key.rawRepresentation)
}

/// Computes HMAC tags with a symmetric key.
public struct HMACSigner<Algorithm: HMACAlgorithm>: Signer {
    public let keyID: KeyID?
    private let key: SymmetricKey

    public init(key: SymmetricKeyMaterial, keyID: KeyID? = nil) throws(JWKError) {
        self.key = try hmacKey(key, for: Algorithm.self)
        self.keyID = keyID
    }

    /// Builds a signer from a symmetric JWK, honouring its `use`, `key_ops` and `alg` restrictions.
    public init(jwk: SymmetricJWK) throws(JWKError) {
        try jwk.metadata.requirePermission(for: .sign, use: .signature, algorithm: Algorithm.identifier)
        try self.init(key: jwk.key, keyID: jwk.metadata.keyID)
    }

    public func sign(_ message: Data) async throws(SigningError) -> Signature<Algorithm> {
        let tag = Data(HMAC<Algorithm.Hash>.authenticationCode(for: message, using: key))
        do {
            return try Signature(rawRepresentation: tag)
        } catch {
            throw .invalidSignature(error)
        }
    }
}

/// Checks HMAC tags with a symmetric key, in constant time.
public struct HMACVerifier<Algorithm: HMACAlgorithm>: Verifier {
    public let keyID: KeyID?
    private let key: SymmetricKey

    public init(key: SymmetricKeyMaterial, keyID: KeyID? = nil) throws(JWKError) {
        self.key = try hmacKey(key, for: Algorithm.self)
        self.keyID = keyID
    }

    /// Builds a verifier from a symmetric JWK, honouring its `use`, `key_ops` and `alg` restrictions.
    public init(jwk: SymmetricJWK) throws(JWKError) {
        try jwk.metadata.requirePermission(for: .verify, use: .signature, algorithm: Algorithm.identifier)
        try self.init(key: jwk.key, keyID: jwk.metadata.keyID)
    }

    public func verify(_ signature: Signature<Algorithm>, for message: Data) throws(VerificationError) {
        let isValid = HMAC<Algorithm.Hash>.isValidAuthenticationCode(
            signature.rawRepresentation,
            authenticating: message,
            using: key
        )
        guard isValid else {
            throw .signatureMismatch(algorithm: Algorithm.identifier)
        }
    }
}
