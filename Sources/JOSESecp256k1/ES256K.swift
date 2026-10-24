import JOSECore

/// ECDSA using secp256k1 and SHA-256 (RFC 8812 §3.2).
///
/// An algorithm added outside JOSECore, the way any add-on algorithm is (DESIGN.md D5): a
/// ``SignatureAlgorithm`` type, with ``Secp256k1Signer`` and ``Secp256k1Verifier`` for it.
public struct ES256K: ECDSASignatureAlgorithm {
    public static let identifier: AlgorithmIdentifier = "ES256K"
    public static let coordinateByteCount = 32

    public init() {}
}
