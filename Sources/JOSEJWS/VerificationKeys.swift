import Foundation
import JOSECore
import JOSEJWK

/// A ``Verifier`` with its algorithm type erased, so that verifiers for different algorithms can
/// be held together and chosen by the `alg` a token names.
public struct AnyVerifier: Sendable {
    public let algorithm: AlgorithmIdentifier
    public let keyID: KeyID?
    private let check: @Sendable (Data, Data) throws(JWSError) -> Void

    public init<V: Verifier>(_ verifier: V) {
        algorithm = V.Algorithm.identifier
        keyID = verifier.keyID
        check = { (signatureBytes: Data, message: Data) throws(JWSError) in
            try Self.verify(signatureBytes, for: message, with: verifier)
        }
    }

    // A function rather than inline in the closure above: inside a closure, `do`/`catch` does
    // not infer the typed error, and the catch blocks below rely on it.
    private static func verify<V: Verifier>(
        _ signatureBytes: Data,
        for message: Data,
        with verifier: V
    ) throws(JWSError) {
        let signature: Signature<V.Algorithm>
        do {
            signature = try Signature(rawRepresentation: signatureBytes)
        } catch {
            throw .malformedSignature(error)
        }
        do {
            try verifier.verify(signature, for: message)
        } catch {
            switch error {
            case .signatureMismatch:
                throw .signatureInvalid(algorithm: V.Algorithm.identifier, keyID: verifier.keyID)
            case .keyOperationFailed:
                throw .verificationFailed(error)
            }
        }
    }

    func verify(signature: Data, message: Data) throws(JWSError) {
        try check(signature, message)
    }
}

/// An algorithm for which a verifier can be built from a ``JWK``. Conform an add-on algorithm to
/// this to make it usable with ``VerificationKeys/init(jwks:allowing:)``.
public protocol JWKVerifiableAlgorithm: SignatureAlgorithm {
    static func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier
}

extension ES256: JWKVerifiableAlgorithm {
    public static func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
        AnyVerifier(try ECDSAVerifier<P256Curve>(jwk: jwk))
    }
}

extension ES384: JWKVerifiableAlgorithm {
    public static func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
        AnyVerifier(try ECDSAVerifier<P384Curve>(jwk: jwk))
    }
}

extension ES512: JWKVerifiableAlgorithm {
    public static func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
        AnyVerifier(try ECDSAVerifier<P521Curve>(jwk: jwk))
    }
}

extension JOSECore.Ed25519: JWKVerifiableAlgorithm {
    public static func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
        AnyVerifier(try Ed25519Verifier<JOSECore.Ed25519>(jwk: jwk))
    }
}

extension EdDSA: JWKVerifiableAlgorithm {
    public static func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
        AnyVerifier(try Ed25519Verifier<EdDSA>(jwk: jwk))
    }
}

/// The keys a JWS may be verified with.
///
/// This is also the list of acceptable algorithms: a token is only ever checked with a verifier
/// whose algorithm equals the token's `alg`, so an algorithm with no verifier here cannot be
/// accepted. There is no separate allow-list to keep in step.
public struct VerificationKeys: Sendable {
    public let verifiers: [AnyVerifier]

    public init(_ verifiers: [AnyVerifier]) {
        self.verifiers = verifiers
    }

    public init(@VerificationKeysBuilder _ build: () throws -> [AnyVerifier]) rethrows {
        verifiers = try build()
    }

    /// Builds verifiers from the keys of a JWK Set, for the named algorithms only.
    ///
    /// Each key yields a verifier for each listed algorithm it is suitable for: right key type,
    /// and permitted by the key's `use`, `key_ops` and `alg`. Keys suitable for none are skipped.
    public init(jwks: JWKSet, allowing algorithms: [any JWKVerifiableAlgorithm.Type]) {
        var verifiers: [AnyVerifier] = []
        for jwk in jwks.keys {
            for algorithm in algorithms {
                do {
                    verifiers.append(try algorithm.verifier(for: jwk))
                } catch {
                    // Expected for most pairs: a P-256 key is not an ES384 key. A key that suits
                    // no algorithm contributes no verifier, and a token needing it then fails
                    // with an error naming its algorithm and key ID.
                    continue
                }
            }
        }
        self.verifiers = verifiers
    }

    /// The algorithms a token may use with these keys.
    public var algorithms: [AlgorithmIdentifier] {
        var seen: [AlgorithmIdentifier] = []
        for verifier in verifiers where !seen.contains(verifier.algorithm) {
            seen.append(verifier.algorithm)
        }
        return seen
    }

    /// The verifiers to try for a signature: those for its algorithm and, when it names a key
    /// ID, for that key or for no particular key.
    func candidates(algorithm: AlgorithmIdentifier, keyID: KeyID?) throws(JWSError) -> [AnyVerifier] {
        let forAlgorithm = verifiers.filter { $0.algorithm == algorithm }
        guard !forAlgorithm.isEmpty else {
            throw .noVerifierForAlgorithm(algorithm: algorithm, offered: algorithms)
        }
        guard let keyID else {
            return forAlgorithm
        }
        let forKey = forAlgorithm.filter { $0.keyID == nil || $0.keyID == keyID }
        guard !forKey.isEmpty else {
            throw .noVerifierForKeyID(keyID: keyID, algorithm: algorithm)
        }
        return forKey
    }
}

@resultBuilder
public struct VerificationKeysBuilder {
    public static func buildExpression<V: Verifier>(_ verifier: V) -> [AnyVerifier] {
        [AnyVerifier(verifier)]
    }

    public static func buildExpression(_ verifier: AnyVerifier) -> [AnyVerifier] {
        [verifier]
    }

    public static func buildExpression(_ verifiers: [AnyVerifier]) -> [AnyVerifier] {
        verifiers
    }

    public static func buildExpression(_ keys: VerificationKeys) -> [AnyVerifier] {
        keys.verifiers
    }

    public static func buildBlock(_ components: [AnyVerifier]...) -> [AnyVerifier] {
        components.flatMap { $0 }
    }

    public static func buildOptional(_ component: [AnyVerifier]?) -> [AnyVerifier] {
        component ?? []
    }

    public static func buildEither(first component: [AnyVerifier]) -> [AnyVerifier] {
        component
    }

    public static func buildEither(second component: [AnyVerifier]) -> [AnyVerifier] {
        component
    }

    public static func buildArray(_ components: [[AnyVerifier]]) -> [AnyVerifier] {
        components.flatMap { $0 }
    }
}
