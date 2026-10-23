/// A signature or MAC algorithm, represented as a type so that keys, signers and signatures can
/// be tied to it at compile time.
///
/// To add an algorithm this package does not ship, declare a type conforming to this protocol
/// and provide ``Signer`` and ``Verifier`` conformances for it. Nothing needs registering.
public protocol SignatureAlgorithm: Sendable {
    /// The value written to, and matched against, the `alg` header parameter.
    static var identifier: AlgorithmIdentifier { get }

    /// The exact size of a signature in its JOSE encoding, or `nil` if the size varies (RSA
    /// signatures, for example, are as long as the key's modulus).
    static var signatureByteCount: Int? { get }
}

/// An ECDSA algorithm, whose JOSE signature is `r || s` (IEEE P1363) rather than DER.
public protocol ECDSASignatureAlgorithm: SignatureAlgorithm {
    /// The size in bytes of one curve coordinate, and so of each of `r` and `s`.
    static var coordinateByteCount: Int { get }
}

extension ECDSASignatureAlgorithm {
    public static var signatureByteCount: Int? {
        coordinateByteCount * 2
    }
}

// Each algorithm is also a value, so that it can be listed where several are accepted (for
// example, the algorithms a JWK Set may be used with).

/// ECDSA using P-256 and SHA-256 (RFC 7518 §3.4).
public struct ES256: ECDSASignatureAlgorithm {
    public static let identifier: AlgorithmIdentifier = "ES256"
    public static let coordinateByteCount = 32

    public init() {}
}

/// ECDSA using P-384 and SHA-384 (RFC 7518 §3.4).
public struct ES384: ECDSASignatureAlgorithm {
    public static let identifier: AlgorithmIdentifier = "ES384"
    public static let coordinateByteCount = 48

    public init() {}
}

/// ECDSA using P-521 and SHA-512 (RFC 7518 §3.4). The curve is P-521; "512" is the hash.
public struct ES512: ECDSASignatureAlgorithm {
    public static let identifier: AlgorithmIdentifier = "ES512"
    public static let coordinateByteCount = 66

    public init() {}
}

/// EdDSA using Ed25519, under its fully-specified name (RFC 9864 §2.2).
///
/// RFC 9864 deprecates the polymorphic ``EdDSA`` identifier in favour of this one. The two are
/// distinct `alg` values over the same key type and signature scheme: a token is signed and
/// verified under whichever one its header names.
public struct Ed25519: SignatureAlgorithm {
    public static let identifier: AlgorithmIdentifier = "Ed25519"
    public static let signatureByteCount: Int? = 64

    public init() {}
}

/// EdDSA with the curve taken from the key (RFC 8037 §3.1). Deprecated by RFC 9864 in favour of
/// ``Ed25519``, but still what most deployed tokens carry.
///
/// The signature size is not fixed by the identifier: 64 bytes with an Ed25519 key, 114 with
/// Ed448.
public struct EdDSA: SignatureAlgorithm {
    public static let identifier: AlgorithmIdentifier = "EdDSA"
    public static let signatureByteCount: Int? = nil

    public init() {}
}

/// HMAC using SHA-256 (RFC 7518 §3.2).
public struct HS256: SignatureAlgorithm {
    public static let identifier: AlgorithmIdentifier = "HS256"
    public static let signatureByteCount: Int? = 32

    public init() {}
}

/// HMAC using SHA-384 (RFC 7518 §3.2).
public struct HS384: SignatureAlgorithm {
    public static let identifier: AlgorithmIdentifier = "HS384"
    public static let signatureByteCount: Int? = 48

    public init() {}
}

/// HMAC using SHA-512 (RFC 7518 §3.2).
public struct HS512: SignatureAlgorithm {
    public static let identifier: AlgorithmIdentifier = "HS512"
    public static let signatureByteCount: Int? = 64

    public init() {}
}

// RSA signatures are as long as the key's modulus, so none of these fix a size.

/// RSASSA-PKCS1-v1_5 using SHA-256 (RFC 7518 §3.3).
public struct RS256: SignatureAlgorithm {
    public static let identifier: AlgorithmIdentifier = "RS256"
    public static let signatureByteCount: Int? = nil

    public init() {}
}

/// RSASSA-PKCS1-v1_5 using SHA-384 (RFC 7518 §3.3).
public struct RS384: SignatureAlgorithm {
    public static let identifier: AlgorithmIdentifier = "RS384"
    public static let signatureByteCount: Int? = nil

    public init() {}
}

/// RSASSA-PKCS1-v1_5 using SHA-512 (RFC 7518 §3.3).
public struct RS512: SignatureAlgorithm {
    public static let identifier: AlgorithmIdentifier = "RS512"
    public static let signatureByteCount: Int? = nil

    public init() {}
}

/// RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (RFC 7518 §3.5).
public struct PS256: SignatureAlgorithm {
    public static let identifier: AlgorithmIdentifier = "PS256"
    public static let signatureByteCount: Int? = nil

    public init() {}
}

/// RSASSA-PSS using SHA-384 and MGF1 with SHA-384 (RFC 7518 §3.5).
public struct PS384: SignatureAlgorithm {
    public static let identifier: AlgorithmIdentifier = "PS384"
    public static let signatureByteCount: Int? = nil

    public init() {}
}

/// RSASSA-PSS using SHA-512 and MGF1 with SHA-512 (RFC 7518 §3.5).
public struct PS512: SignatureAlgorithm {
    public static let identifier: AlgorithmIdentifier = "PS512"
    public static let signatureByteCount: Int? = nil

    public init() {}
}
