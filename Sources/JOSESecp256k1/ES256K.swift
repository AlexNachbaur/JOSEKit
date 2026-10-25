#if canImport(P256K)
    import JOSECore
    import JOSEJWK
    import JOSEJWS

    /// ECDSA using secp256k1 and SHA-256 (RFC 8812 §3.2).
    ///
    /// An algorithm added outside JOSECore, the way any add-on algorithm is (DESIGN.md D5). It signs
    /// and verifies with ``JOSEJWK/ECDSASigner`` and ``JOSEJWK/ECDSAVerifier`` on ``Secp256k1Curve``.
    public struct ES256K: ECDSASignatureAlgorithm {
        public static let identifier: AlgorithmIdentifier = "ES256K"
        public static let coordinateByteCount = 32

        public init() {}
    }

    extension ES256K: JWKVerifiableAlgorithm {
        public func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
            AnyVerifier(try ECDSAVerifier<Secp256k1Curve>(jwk: jwk))
        }
    }

    // So that `allowing: [.es256, .es256k]` reads naturally (SE-0299).
    extension JWKVerifiableAlgorithm where Self == ES256K {
        public static var es256k: ES256K { ES256K() }
    }
#endif
