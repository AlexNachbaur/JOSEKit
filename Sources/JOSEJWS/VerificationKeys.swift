import Foundation
import JOSECore
import JOSEJWK

/// A ``Verifier`` with its algorithm type erased, so that verifiers for different algorithms can
/// be held together and chosen by the `alg` a token names.
public struct AnyVerifier: Sendable {
    public let algorithm: AlgorithmIdentifier
    public let keyID: KeyID?
    private let check: @Sendable (Data, Data) async throws(JWSError) -> Void

    public init<V: Verifier>(_ verifier: V) {
        algorithm = V.Algorithm.identifier
        keyID = verifier.keyID
        check = { (signatureBytes: Data, message: Data) async throws(JWSError) in
            try await Self.verify(signatureBytes, for: message, with: verifier)
        }
    }

    // A function rather than inline in the closure above: inside a closure, `do`/`catch` does
    // not infer the typed error, and the catch blocks below rely on it.
    private static func verify<V: Verifier>(
        _ signatureBytes: Data,
        for message: Data,
        with verifier: V
    ) async throws(JWSError) {
        let signature: Signature<V.Algorithm>
        do {
            signature = try Signature(rawRepresentation: signatureBytes)
        } catch {
            throw .malformedSignature(error)
        }
        do {
            try await verifier.verify(signature, for: message)
        } catch {
            switch error {
            case .signatureMismatch:
                throw .signatureInvalid(algorithm: V.Algorithm.identifier, keyID: verifier.keyID)
            case .keyOperationFailed:
                throw .verificationFailed(error)
            }
        }
    }

    func verify(signature: Data, message: Data) async throws(JWSError) {
        try await check(signature, message)
    }
}

/// An algorithm for which a verifier can be built from a ``JWK``, so that it can be listed in
/// ``VerificationKeys/init(jwks:allowing:)`` and ``HeaderKeyResolver``.
///
/// The built-in ones are the cases of ``JWSAlgorithm``. An add-on algorithm conforms with an
/// instance, as the built-in types do: `ES256()`.
public protocol JWKVerifiableAlgorithm: Sendable {
    /// The algorithm's `alg`.
    var identifier: AlgorithmIdentifier { get }

    /// A verifier for this algorithm, if the key's type and its `use`, `key_ops` and `alg`
    /// allow it.
    func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier
}

extension JWKVerifiableAlgorithm where Self: SignatureAlgorithm {
    public var identifier: AlgorithmIdentifier {
        Self.identifier
    }
}

extension ES256: JWKVerifiableAlgorithm {
    public func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
        AnyVerifier(try ECDSAVerifier<P256Curve>(jwk: jwk))
    }
}

extension ES384: JWKVerifiableAlgorithm {
    public func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
        AnyVerifier(try ECDSAVerifier<P384Curve>(jwk: jwk))
    }
}

extension ES512: JWKVerifiableAlgorithm {
    public func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
        AnyVerifier(try ECDSAVerifier<P521Curve>(jwk: jwk))
    }
}

extension JOSECore.Ed25519: JWKVerifiableAlgorithm {
    public func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
        AnyVerifier(try Ed25519Verifier<JOSECore.Ed25519>(jwk: jwk))
    }
}

extension EdDSA: JWKVerifiableAlgorithm {
    public func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
        AnyVerifier(try Ed25519Verifier<EdDSA>(jwk: jwk))
    }
}

extension RS256: JWKVerifiableAlgorithm {
    public func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
        AnyVerifier(try RSAVerifier<RS256>(jwk: jwk))
    }
}

extension RS384: JWKVerifiableAlgorithm {
    public func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
        AnyVerifier(try RSAVerifier<RS384>(jwk: jwk))
    }
}

extension RS512: JWKVerifiableAlgorithm {
    public func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
        AnyVerifier(try RSAVerifier<RS512>(jwk: jwk))
    }
}

extension PS256: JWKVerifiableAlgorithm {
    public func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
        AnyVerifier(try RSAVerifier<PS256>(jwk: jwk))
    }
}

extension PS384: JWKVerifiableAlgorithm {
    public func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
        AnyVerifier(try RSAVerifier<PS384>(jwk: jwk))
    }
}

extension PS512: JWKVerifiableAlgorithm {
    public func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
        AnyVerifier(try RSAVerifier<PS512>(jwk: jwk))
    }
}

/// The signature algorithms whose verifiers this package can build from a JWK. Each case
/// delegates to the type that implements it, such as ``ES256``.
public enum JWSAlgorithm: JWKVerifiableAlgorithm, CaseIterable, Hashable {
    case es256
    case es384
    case es512
    case ed25519
    case edDSA
    case rs256
    case rs384
    case rs512
    case ps256
    case ps384
    case ps512

    /// The type that implements this algorithm.
    public var algorithm: any JWKVerifiableAlgorithm {
        switch self {
        case .es256:
            return ES256()
        case .es384:
            return ES384()
        case .es512:
            return ES512()
        case .ed25519:
            return JOSECore.Ed25519()
        case .edDSA:
            return EdDSA()
        case .rs256:
            return RS256()
        case .rs384:
            return RS384()
        case .rs512:
            return RS512()
        case .ps256:
            return PS256()
        case .ps384:
            return PS384()
        case .ps512:
            return PS512()
        }
    }

    public var identifier: AlgorithmIdentifier {
        algorithm.identifier
    }

    public func verifier(for jwk: JWK) throws(JWKError) -> AnyVerifier {
        try algorithm.verifier(for: jwk)
    }
}

// So that `allowing: [.es256, .ps256]` reads naturally (SE-0299).
extension JWKVerifiableAlgorithm where Self == ES256 {
    public static var es256: ES256 { ES256() }
}

extension JWKVerifiableAlgorithm where Self == ES384 {
    public static var es384: ES384 { ES384() }
}

extension JWKVerifiableAlgorithm where Self == ES512 {
    public static var es512: ES512 { ES512() }
}

extension JWKVerifiableAlgorithm where Self == JOSECore.Ed25519 {
    public static var ed25519: JOSECore.Ed25519 { JOSECore.Ed25519() }
}

extension JWKVerifiableAlgorithm where Self == EdDSA {
    public static var edDSA: EdDSA { EdDSA() }
}

extension JWKVerifiableAlgorithm where Self == RS256 {
    public static var rs256: RS256 { RS256() }
}

extension JWKVerifiableAlgorithm where Self == RS384 {
    public static var rs384: RS384 { RS384() }
}

extension JWKVerifiableAlgorithm where Self == RS512 {
    public static var rs512: RS512 { RS512() }
}

extension JWKVerifiableAlgorithm where Self == PS256 {
    public static var ps256: PS256 { PS256() }
}

extension JWKVerifiableAlgorithm where Self == PS384 {
    public static var ps384: PS384 { PS384() }
}

extension JWKVerifiableAlgorithm where Self == PS512 {
    public static var ps512: PS512 { PS512() }
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
    public init(jwks: JWKSet, allowing algorithms: [any JWKVerifiableAlgorithm]) {
        var verifiers: [AnyVerifier] = []
        for jwk in jwks.keys {
            // A key that suits no algorithm contributes no verifier, and a token needing it then
            // fails with an error naming its algorithm and key ID.
            verifiers += Self.verifiers(for: jwk, allowing: algorithms).verifiers
        }
        self.verifiers = verifiers
    }

    /// The verifiers one key yields for `algorithms`, and why it yielded none for the others.
    /// Most failures are expected (a P-256 key is not an ES384 key); they are returned so that a
    /// caller with a single key can report the real reason it was unusable.
    static func verifiers(
        for jwk: JWK,
        allowing algorithms: [any JWKVerifiableAlgorithm]
    ) -> (verifiers: [AnyVerifier], failures: [JWKError]) {
        var verifiers: [AnyVerifier] = []
        var failures: [JWKError] = []
        for algorithm in algorithms {
            do {
                verifiers.append(try algorithm.verifier(for: jwk))
            } catch {
                failures.append(error)
            }
        }
        return (verifiers, failures)
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
