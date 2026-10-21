import Foundation
import JOSECore
import JOSEJWK

/// Why verification keys could not be obtained from a header.
public enum KeyResolutionError: Error, Sendable, Equatable {
    /// The header names no key source this resolver is configured to use.
    case noUsableKeySource(headerParameters: [String])
    /// `jku` is not an HTTPS URL on the resolver's allow-list (RFC 8725 §3.10).
    case jwkSetURLNotAllowed(String)
    case jwkSetURLInvalid(String)
    /// The ``JWKSetProvider`` failed.
    case jwkSetUnavailable(url: String, underlying: UnderlyingError)
    /// The ``CertificateChainValidator`` refused the chain.
    case certificateChainRejected(underlying: UnderlyingError)
    /// `x5c` is present but not an array of base64 strings.
    case certificateChainMalformed(reason: String)
    /// `x5t` or `x5t#S256` does not match the first certificate in `x5c` (RFC 7515 §4.1.7, §4.1.8).
    case certificateThumbprintMismatch(parameter: String)
    /// Both `jwk` and `x5c` are present and do not describe the same key (RFC 7515 §4.1.6).
    case embeddedKeyDoesNotMatchCertificate
    /// The resolved key is not usable for the token's algorithm.
    case keyNotUsable(JWKError)
}

extension KeyResolutionError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .noUsableKeySource(let headerParameters):
            return
                "header names no key source this resolver uses (present: \(headerParameters.joined(separator: ", ")))"
        case .jwkSetURLNotAllowed(let url):
            return "\"jku\" \(url) is not on the allow-list of JWK Set URLs"
        case .jwkSetURLInvalid(let url):
            return "\"jku\" \(url) is not a valid URL"
        case .jwkSetUnavailable(let url, let underlying):
            return "the JWK Set at \(url) could not be obtained: \(underlying)"
        case .certificateChainRejected(let underlying):
            return "\"x5c\" certificate chain was rejected: \(underlying)"
        case .certificateChainMalformed(let reason):
            return "\"x5c\" is malformed: \(reason)"
        case .certificateThumbprintMismatch(let parameter):
            return "\"\(parameter)\" does not match the first certificate in \"x5c\""
        case .embeddedKeyDoesNotMatchCertificate:
            return "\"jwk\" and \"x5c\" describe different keys"
        case .keyNotUsable(let error):
            return "resolved key is not usable: \(error)"
        }
    }
}

/// Supplies the JWK Set published at a URL. Implement this to use your own HTTP client, caching
/// or storage; ``URLSessionJWKSetProvider`` is the stock implementation.
public protocol JWKSetProvider: Sendable {
    func jwkSet(at url: URL) async throws -> JWKSet
}

extension VerificationKeys {
    /// Fetches the JWK Set at a URL known out of band, such as an OpenID Connect issuer's
    /// `jwks_uri`, and builds verifiers from it for the named algorithms, as
    /// ``init(jwks:allowing:)`` does.
    ///
    /// The URL comes from your configuration, never from a token. Pass a
    /// ``CachingJWKSetProvider`` so that the set is not fetched for every token.
    public init(
        jwksAt url: URL,
        provider: any JWKSetProvider,
        allowing algorithms: [any JWKVerifiableAlgorithm.Type]
    ) async throws(KeyResolutionError) {
        let set: JWKSet
        do {
            set = try await provider.jwkSet(at: url)
        } catch {
            throw .jwkSetUnavailable(url: url.absoluteString, underlying: UnderlyingError(error))
        }
        self.init(jwks: set, allowing: algorithms)
    }
}

/// Validates an X.509 certificate chain and returns the public key of its first certificate.
///
/// `chain` holds DER-encoded certificates, the signer's first, as carried in `x5c`. An
/// implementation decides what "valid" means: which anchors are trusted, whether revocation is
/// checked, what names are expected. ``SecTrustCertificateChainValidator`` is the stock
/// implementation on Apple platforms; elsewhere, supply one built on a certificate library.
public protocol CertificateChainValidator: Sendable {
    func validate(chain: [Data]) async throws -> JWK
}

/// Turns the key-identifying parameters of a JWS header into verification keys.
///
/// Each source is opt-in and, once opted in, bounded:
///
/// - `jku`: used only when a ``JWKSetProvider`` is set **and** the URL is on ``allowedJWKSetURLs``.
/// - `x5c`: used only when a ``CertificateChainValidator`` is set.
/// - `jwk`: used only when ``allowsEmbeddedKey`` is on. A key the token carries proves nothing
///   on its own; this is for proof-of-possession designs where the application checks the key's
///   thumbprint against something it already trusts.
///
/// A resolver is not a trust decision by itself: it answers "which keys may this token be
/// checked against", and ``VerificationKeys`` still restricts the algorithms.
public struct HeaderKeyResolver: Sendable {
    public var jwkSetProvider: (any JWKSetProvider)?
    /// Exact URLs (scheme, host, path) that `jku` may name. HTTPS only.
    public var allowedJWKSetURLs: Set<URL>
    public var certificateChainValidator: (any CertificateChainValidator)?
    public var allowsEmbeddedKey: Bool
    /// The algorithms a resolved key may be used with.
    public let algorithms: [any JWKVerifiableAlgorithm.Type]

    public init(
        algorithms: [any JWKVerifiableAlgorithm.Type],
        jwkSetProvider: (any JWKSetProvider)? = nil,
        allowedJWKSetURLs: Set<URL> = [],
        certificateChainValidator: (any CertificateChainValidator)? = nil,
        allowsEmbeddedKey: Bool = false
    ) {
        self.algorithms = algorithms
        self.jwkSetProvider = jwkSetProvider
        self.allowedJWKSetURLs = allowedJWKSetURLs
        self.certificateChainValidator = certificateChainValidator
        self.allowsEmbeddedKey = allowsEmbeddedKey
    }

    /// The keys `header` points at, from every configured source it names.
    public func verificationKeys<Custom: HeaderParameters>(
        for header: JWSHeader<Custom>
    ) async throws(KeyResolutionError) -> VerificationKeys {
        var verifiers: [AnyVerifier] = []
        var present: [String] = []

        if let jwkSetURL = header.parameters.jwkSetURL {
            present.append("jku")
            if let jwkSetProvider {
                let set = try await Self.fetch(jwkSetURL, from: jwkSetProvider, allowed: allowedJWKSetURLs)
                verifiers += VerificationKeys(jwks: set, allowing: algorithms).verifiers
            }
        }

        var certificateKey: JWK?
        if let chain = header.parameters.x509CertificateChain {
            present.append("x5c")
            if let certificateChainValidator {
                let leaf = try await Self.validate(chain, header: header, with: certificateChainValidator)
                certificateKey = leaf
                verifiers += try resolvedVerifiers(for: leaf, keyID: header.keyID)
            }
        }

        if let embedded = header.parameters.jwk {
            present.append("jwk")
            if let certificateKey {
                guard embedded.key == certificateKey.key else {
                    throw .embeddedKeyDoesNotMatchCertificate
                }
            } else if allowsEmbeddedKey {
                verifiers += try resolvedVerifiers(for: embedded, keyID: header.keyID)
            }
        }

        guard !verifiers.isEmpty else {
            throw .noUsableKeySource(headerParameters: present)
        }
        return VerificationKeys(verifiers)
    }

    private static func fetch(
        _ urlString: String,
        from provider: any JWKSetProvider,
        allowed: Set<URL>
    ) async throws(KeyResolutionError) -> JWKSet {
        guard let url = URL(string: urlString) else {
            throw .jwkSetURLInvalid(urlString)
        }
        guard url.scheme?.lowercased() == "https", allowed.contains(url) else {
            throw .jwkSetURLNotAllowed(urlString)
        }
        do {
            return try await provider.jwkSet(at: url)
        } catch {
            throw .jwkSetUnavailable(url: urlString, underlying: UnderlyingError(error))
        }
    }

    private static func validate<Custom: HeaderParameters>(
        _ chain: [String],
        header: JWSHeader<Custom>,
        with validator: any CertificateChainValidator
    ) async throws(KeyResolutionError) -> JWK {
        guard !chain.isEmpty else {
            throw .certificateChainMalformed(reason: "the array is empty")
        }
        var certificates: [Data] = []
        for (index, text) in chain.enumerated() {
            // x5c uses standard base64, not base64url (RFC 7515 §4.1.6).
            guard let der = Data(base64Encoded: text), !der.isEmpty else {
                throw .certificateChainMalformed(reason: "element \(index) is not base64")
            }
            certificates.append(der)
        }
        let thumbprints: [(CertificateDigest, String?)] = [
            (.sha1, header.parameters.x509CertificateSHA1Thumbprint),
            (.sha256, header.parameters.x509CertificateSHA256Thumbprint),
        ]
        for case (let digest, let thumbprint?) in thumbprints {
            guard thumbprint == String(base64URLEncoding: digest.digest(of: certificates[0])) else {
                throw .certificateThumbprintMismatch(parameter: digest.parameter)
            }
        }
        do {
            return try await validator.validate(chain: certificates)
        } catch {
            throw .certificateChainRejected(underlying: UnderlyingError(error))
        }
    }

    /// Verifiers for a single resolved key. The token's `kid` is applied to a key that has none,
    /// so that key selection works the same as for a key from a JWK Set.
    private func resolvedVerifiers(for jwk: JWK, keyID: KeyID?) throws(KeyResolutionError) -> [AnyVerifier] {
        var key = jwk
        if key.metadata.keyID == nil {
            key.metadata.keyID = keyID
        }
        let (verifiers, failures) = VerificationKeys.verifiers(for: key, allowing: algorithms)
        guard !verifiers.isEmpty else {
            throw .keyNotUsable(
                failures.first
                    ?? .keyTypeMismatch(expected: "a key for one of the allowed algorithms", found: key.keyType)
            )
        }
        return verifiers
    }
}
