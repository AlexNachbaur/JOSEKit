import Foundation
import JOSECore
import JOSEJWE
import JOSEJWK
import JOSEJWS
import JOSEJWT

/// Why an encrypted or nested JWT could not be read or produced.
public enum EncryptedJWTError: Error, Sendable, Equatable {
    /// The JWE layer refused the token: malformed, wrong algorithm, decryption failed.
    case jwe(JWEError)
    /// The claims, or the nested JWT, were refused.
    case jwt(JWTError)
    /// The token's `cty` says its content is another JWT. Read it with ``NestedJWT``, which
    /// requires the inner token's signature to be verified.
    case contentIsNestedJWT
    /// A nested JWT was expected, and the token's `cty` is not `JWT` (RFC 7519 §5.2).
    case contentIsNotNestedJWT(contentType: String?)
    /// The decrypted content of a nested JWT is not text.
    case nestedTokenNotUTF8
    /// The header repeats a claim (RFC 7519 §5.3) with a different value from the claims set.
    case replicatedClaimMismatch(name: String)
}

extension EncryptedJWTError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .jwe(let error):
            return "encrypted JWT is not a valid JWE: \(error)"
        case .jwt(let error):
            return "encrypted JWT's content was refused: \(error)"
        case .contentIsNestedJWT:
            return "encrypted JWT's \"cty\" is JWT: its content is a nested JWT and must be read as one"
        case .contentIsNotNestedJWT(let contentType):
            return "expected a nested JWT, but \"cty\" is \(contentType.map { "\"\($0)\"" } ?? "absent")"
        case .nestedTokenNotUTF8:
            return "decrypted content of the nested JWT is not UTF-8 text"
        case .replicatedClaimMismatch(let name):
            return "header parameter \"\(name)\" repeats a claim but does not equal it"
        }
    }
}

let nestedContentType: MediaType = "JWT"

/// RFC 7519 §5.3: `iss`, `sub` and `aud` may be repeated in the header of an encrypted JWT so
/// that they can be read without decrypting. Where they are, they must equal the real claims.
private func checkReplicatedClaims(
    header: [String: JSONValue],
    claims: [String: JSONValue]
) throws(EncryptedJWTError) {
    for name in ["iss", "sub", "aud"] {
        guard let replicated = header[name] else {
            continue
        }
        guard claims[name] == replicated else {
            throw .replicatedClaimMismatch(name: name)
        }
    }
}

/// A JWT whose claims are the plaintext of a JWE (RFC 7519 §3, "encrypted JWT").
///
/// Encryption keeps the claims confidential. Whether it also says who wrote them depends on the
/// key management algorithm: with a shared symmetric key, only a holder of that key can have
/// produced the token; with a public key (RSA-OAEP, ECDH-ES), **anyone** can. If you need to know
/// the issuer of a token encrypted to your public key, it must be signed as well: see
/// ``NestedJWT``.
public struct EncryptedJWT<Custom: Codable & Sendable, Header: HeaderParameters>: Sendable {
    private init() {}

    /// An encrypted JWT that has not been decrypted.
    public struct Encrypted: Sendable {
        let jwe: JWE<Header>.Encrypted
        /// The header as received. Nothing in it is authenticated until the token is decrypted.
        public var header: JWEHeader<Header> {
            jwe.header
        }

        /// Parses an encrypted JWT, which is always in the JWE Compact Serialization.
        public init(compact: String) throws(EncryptedJWTError) {
            do {
                jwe = try JWE<Header>.Encrypted(compact: compact)
            } catch {
                throw .jwe(error)
            }
            guard jwe.header.contentType != nestedContentType else {
                throw .contentIsNestedJWT
            }
        }

        /// Decrypts the token. The result's claims have still not been validated.
        ///
        /// - Parameter maximumDecompressedByteCount: For a compressed token (`zip`), the largest
        ///   claims set accepted after decompression; 0 or less refuses compressed tokens.
        public func decrypt(
            with keys: DecryptionKeys,
            contentEncryptions: [any ContentEncryptionAlgorithm.Type] = ContentEncryption.standard,
            maximumDecompressedByteCount: Int = JWECompression.defaultMaximumDecompressedByteCount
        ) async throws(EncryptedJWTError) -> Decrypted {
            let decrypted: JWE<Header>.Decrypted
            do {
                decrypted = try await jwe.decrypt(
                    with: keys,
                    contentEncryptions: contentEncryptions,
                    maximumDecompressedByteCount: maximumDecompressedByteCount
                )
            } catch {
                throw .jwe(error)
            }
            let claims: JWTClaims<Custom>
            let raw: [String: JSONValue]
            do {
                (claims, raw) = try JWTClaims<Custom>.parse(decrypted.plaintext)
            } catch {
                throw .jwt(error)
            }
            try checkReplicatedClaims(header: decrypted.header.rawParameters, claims: raw)
            return Decrypted(header: decrypted.header, unvalidatedClaims: claims, rawClaims: raw)
        }
    }

    /// An encrypted JWT that decrypted. Whether it is expired, or meant for you, is not yet known.
    public struct Decrypted: Sendable {
        public let header: JWEHeader<Header>
        /// The claims, not yet checked against any policy.
        public let unvalidatedClaims: JWTClaims<Custom>
        /// Every claim as it was received, including ones no typed property covers. Not yet
        /// checked against any policy.
        public let rawClaims: [String: JSONValue]

        /// Checks the claims against `policy`. The policy's type rule applies to the JWE header's
        /// `typ`.
        public func validate(_ policy: JWTValidationPolicy) throws(JWTValidationError) -> Validated {
            try policy.validate(unvalidatedClaims, type: header.type)
            return Validated(header: header, claims: unvalidatedClaims, rawClaims: rawClaims)
        }
    }

    /// An encrypted JWT that decrypted and whose claims satisfied a validation policy.
    public struct Validated: Sendable {
        public let header: JWEHeader<Header>
        public let claims: JWTClaims<Custom>
        /// Every claim as it was received, including ones no typed property covers.
        public let rawClaims: [String: JSONValue]
    }

    /// Encrypts `claims` to one recipient and returns the JWT.
    public static func encrypt<Recipient: KeyEncrypter, Encryption: ContentEncryptionAlgorithm>(
        _ claims: JWTClaims<Custom>,
        to recipient: Recipient,
        using contentEncryption: Encryption.Type,
        header: JWEHeaderParameters<Header>
    ) async throws(EncryptedJWTError) -> String {
        let payload: Data
        do {
            payload = try claims.jsonRepresentation()
        } catch {
            throw .jwt(error)
        }
        var header = header
        // `cty: JWT` is reserved for nesting; on a token whose content is a claims set it would
        // send readers looking for an inner JWT.
        if header.contentType == nestedContentType {
            header.contentType = nil
        }
        do {
            return try await JWE<Header>.encrypt(payload, to: recipient, using: contentEncryption, header: header)
                .compactSerialization()
        } catch {
            throw .jwe(error)
        }
    }
}

extension EncryptedJWT where Header == EmptyHeaderParameters {
    /// Encrypts `claims` to one recipient and returns the JWT.
    ///
    /// - Parameter type: The header's `typ`. Defaults to `JWT`.
    public static func encrypt<Recipient: KeyEncrypter, Encryption: ContentEncryptionAlgorithm>(
        _ claims: JWTClaims<Custom>,
        to recipient: Recipient,
        using contentEncryption: Encryption.Type,
        type: MediaType? = "JWT"
    ) async throws(EncryptedJWTError) -> String {
        try await encrypt(claims, to: recipient, using: contentEncryption, header: JWEHeaderParameters(type: type))
    }
}

/// An encrypted JWT with registered claims and registered header parameters only.
public typealias SimpleEncryptedJWT = EncryptedJWT<EmptyClaims, EmptyHeaderParameters>

/// A signed JWT carried inside a JWE (RFC 7519 §5.2, §11.2): sign, then encrypt.
///
/// A nested JWT moves through the same kinds of types as its siblings. ``Encrypted`` is what
/// parsing gives you; ``Decrypted`` holds the outer header and the signed JWT inside, still
/// unverified. Its claims are reachable only the way any signed JWT's are, by verifying the
/// signature and then validating the claims, so encryption cannot be mistaken for proof of who
/// issued the token.
///
/// `Custom` and `Header` describe the inner, signed JWT. The outer header has registered
/// parameters only.
public struct NestedJWT<Custom: Codable & Sendable, Header: HeaderParameters>: Sendable {
    /// The signed JWT inside.
    public typealias Inner = JWT<Custom, Header>

    private init() {}

    /// A nested JWT that has not been decrypted.
    public struct Encrypted: Sendable {
        let jwe: SimpleJWE.Encrypted
        /// The outer header as received. Nothing in it is authenticated until the token is
        /// decrypted.
        public var header: JWEHeader<EmptyHeaderParameters> {
            jwe.header
        }

        /// Parses a nested JWT, which is always in the JWE Compact Serialization. Its `cty` must
        /// be `JWT` (RFC 7519 §5.2).
        public init(compact: String) throws(EncryptedJWTError) {
            do {
                jwe = try SimpleJWE.Encrypted(compact: compact)
            } catch {
                throw .jwe(error)
            }
            guard jwe.header.contentType == nestedContentType else {
                throw .contentIsNotNestedJWT(contentType: jwe.header.contentType?.rawValue)
            }
        }

        /// Decrypts the outer token and returns the signed JWT inside it, **unverified**.
        ///
        /// - Parameter maximumDecompressedByteCount: For a compressed token (`zip`), the largest
        ///   inner token accepted after decompression; 0 or less refuses compressed tokens.
        public func decrypt(
            with keys: DecryptionKeys,
            contentEncryptions: [any ContentEncryptionAlgorithm.Type] = ContentEncryption.standard,
            maximumDecompressedByteCount: Int = JWECompression.defaultMaximumDecompressedByteCount
        ) async throws(EncryptedJWTError) -> Decrypted {
            let decrypted: SimpleJWE.Decrypted
            do {
                decrypted = try await jwe.decrypt(
                    with: keys,
                    contentEncryptions: contentEncryptions,
                    maximumDecompressedByteCount: maximumDecompressedByteCount
                )
            } catch {
                throw .jwe(error)
            }
            let compact = try Self.text(decrypted.plaintext)
            let inner: JWT<Custom, Header>.Unverified
            do {
                inner = try JWT<Custom, Header>.Unverified(compact: compact)
            } catch {
                throw .jwt(error)
            }
            return Decrypted(header: decrypted.header, inner: inner)
        }

        /// Strict decoding: the inner token is ASCII, and anything that is not valid UTF-8 is
        /// not a JWT.
        private static func text(_ plaintext: Data) throws(EncryptedJWTError) -> String {
            var decoder = UTF8()
            var iterator = plaintext.makeIterator()
            var scalars = String.UnicodeScalarView()
            while true {
                switch decoder.decode(&iterator) {
                case .scalarValue(let scalar):
                    scalars.append(scalar)
                case .emptyInput:
                    return String(scalars)
                case .error:
                    throw .nestedTokenNotUTF8
                }
            }
        }
    }

    /// A nested JWT whose outer layer decrypted. The signed JWT inside has not been verified.
    public struct Decrypted: Sendable {
        /// The outer header, authenticated by the decryption.
        public let header: JWEHeader<EmptyHeaderParameters>
        /// The signed JWT inside, not yet verified. Prefer ``verify(with:)``, which also checks
        /// claims the outer header repeats.
        public let inner: JWT<Custom, Header>.Unverified

        /// Verifies the inner JWT's signature, and checks that any `iss`, `sub` or `aud` the outer
        /// header repeats (RFC 7519 §5.3) equals the signed claim.
        public func verify(with keys: VerificationKeys) async throws(EncryptedJWTError) -> Inner.Verified {
            let verified: Inner.Verified
            do {
                verified = try await inner.verify(with: keys)
            } catch {
                throw .jwt(error)
            }
            try checkReplicatedClaims(header: header.rawParameters, claims: verified.rawClaims)
            return verified
        }

        /// Resolves keys from the inner header's `jku`, `x5c` or `jwk` with `resolver`, then
        /// verifies as ``verify(with:)`` does.
        public func verify(resolving resolver: HeaderKeyResolver) async throws(EncryptedJWTError) -> Inner.Verified {
            let verified: Inner.Verified
            do {
                verified = try await inner.verify(resolving: resolver)
            } catch {
                throw .jwt(error)
            }
            try checkReplicatedClaims(header: header.rawParameters, claims: verified.rawClaims)
            return verified
        }
    }

    /// Signs `claims`, then encrypts the signed JWT to one recipient.
    ///
    /// - Parameters:
    ///   - header: The header of the inner, signed JWT.
    ///   - type: The outer JWE header's `typ`. Its `cty` is always `JWT`, as RFC 7519 §5.2 requires.
    public static func signThenEncrypt<
        S: Signer,
        Recipient: KeyEncrypter,
        Encryption: ContentEncryptionAlgorithm
    >(
        _ claims: JWTClaims<Custom>,
        signedBy signer: S,
        header: JWSHeaderParameters<Header>,
        encryptedTo recipient: Recipient,
        using contentEncryption: Encryption.Type,
        type: MediaType? = nil
    ) async throws(EncryptedJWTError) -> String {
        let inner: String
        do {
            inner = try await JWT<Custom, Header>.sign(claims, with: signer, header: header)
        } catch {
            throw .jwt(error)
        }
        do {
            return try await SimpleJWE.encrypt(
                Data(inner.utf8),
                to: recipient,
                using: contentEncryption,
                header: JWEHeaderParameters(type: type, contentType: nestedContentType)
            ).compactSerialization()
        } catch {
            throw .jwe(error)
        }
    }
}

extension NestedJWT where Header == EmptyHeaderParameters {
    /// Signs `claims`, then encrypts the signed JWT to one recipient.
    public static func signThenEncrypt<
        S: Signer,
        Recipient: KeyEncrypter,
        Encryption: ContentEncryptionAlgorithm
    >(
        _ claims: JWTClaims<Custom>,
        signedBy signer: S,
        encryptedTo recipient: Recipient,
        using contentEncryption: Encryption.Type
    ) async throws(EncryptedJWTError) -> String {
        try await signThenEncrypt(
            claims,
            signedBy: signer,
            header: JWSHeaderParameters(type: "JWT"),
            encryptedTo: recipient,
            using: contentEncryption
        )
    }
}

/// A nested JWT whose inner token has registered claims and registered header parameters only.
public typealias SimpleNestedJWT = NestedJWT<EmptyClaims, EmptyHeaderParameters>
