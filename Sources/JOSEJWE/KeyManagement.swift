import Foundation
import JOSECore
import JOSEJWK

/// A key management algorithm, the `alg` of a JWE (RFC 7518 §4), as a type.
///
/// To add one this package does not ship, declare a type conforming to this protocol and provide
/// ``KeyEncrypter`` and ``KeyDecrypter`` conformances for it.
public protocol KeyManagementAlgorithm: Sendable {
    static var identifier: AlgorithmIdentifier { get }
}

/// What a ``KeyEncrypter`` is asked to do for one recipient.
public struct KeyEncryptionRequest: Sendable {
    /// The JWE's `enc`.
    public let contentEncryption: AlgorithmIdentifier
    /// The size of key that `enc` needs.
    public let keyByteCount: Int
    /// The content encryption key already chosen for an earlier recipient of the same JWE, which
    /// this recipient must be given too. `nil` for the first recipient, who decides the key.
    public let contentEncryptionKey: Data?

    public init(contentEncryption: AlgorithmIdentifier, keyByteCount: Int, contentEncryptionKey: Data?) {
        self.contentEncryption = contentEncryption
        self.keyByteCount = keyByteCount
        self.contentEncryptionKey = contentEncryptionKey
    }

    /// The key to wrap: the one already chosen, or a new random one.
    public func keyToWrap() -> Data {
        contentEncryptionKey ?? SymmetricKeyMaterial(randomByteCount: keyByteCount).rawRepresentation
    }
}

public struct KeyEncryptionResult: Sendable {
    public let contentEncryptionKey: Data
    /// The JWE Encrypted Key. Empty for algorithms that do not wrap a key.
    public let encryptedKey: Data
    /// Header parameters the recipient needs in order to recover the key, such as `epk`.
    public let headerParameters: [String: JSONValue]

    public init(contentEncryptionKey: Data, encryptedKey: Data, headerParameters: [String: JSONValue] = [:]) {
        self.contentEncryptionKey = contentEncryptionKey
        self.encryptedKey = encryptedKey
        self.headerParameters = headerParameters
    }
}

/// Something that can make a content encryption key available to one recipient.
///
/// Encryption is `async`, like decryption, so that a key held by a remote service or in hardware
/// can conform.
public protocol KeyEncrypter<Algorithm>: Sendable {
    associatedtype Algorithm: KeyManagementAlgorithm

    /// Identifies the recipient's key. Written to the `kid` header parameter when present.
    var keyID: KeyID? { get }

    func encryptKey(_ request: KeyEncryptionRequest) async throws(JWEError) -> KeyEncryptionResult
}

/// What a ``KeyDecrypter`` is given to recover the content encryption key.
public struct KeyDecryptionRequest: Sendable {
    public let encryptedKey: Data
    public let contentEncryption: AlgorithmIdentifier
    public let keyByteCount: Int
    /// Every header parameter that applies to this recipient.
    public let header: [String: JSONValue]

    public init(
        encryptedKey: Data,
        contentEncryption: AlgorithmIdentifier,
        keyByteCount: Int,
        header: [String: JSONValue]
    ) {
        self.encryptedKey = encryptedKey
        self.contentEncryption = contentEncryption
        self.keyByteCount = keyByteCount
        self.header = header
    }

    /// A header parameter that must be a base64url string, decoded.
    public func requiredBytes(_ name: String, for algorithm: AlgorithmIdentifier) throws(JWEError) -> Data {
        guard let value = header[name] else {
            throw .missingHeaderParameter(name: name, algorithm: algorithm)
        }
        return try Self.bytes(value, name: name)
    }

    /// An optional header parameter that must be a base64url string when present.
    public func optionalBytes(_ name: String) throws(JWEError) -> Data? {
        guard let value = header[name] else {
            return nil
        }
        return try Self.bytes(value, name: name)
    }

    private static func bytes(_ value: JSONValue, name: String) throws(JWEError) -> Data {
        guard case .string(let text) = value else {
            throw .headerParameterWrongType(name: name, expected: "a base64url string")
        }
        do {
            return try Base64URL.decode(text)
        } catch {
            throw .invalidBase64URL(part: "header parameter \"\(name)\"", error)
        }
    }
}

/// A key management algorithm whose decrypter can be built from a private JWK, so that it can
/// be listed in ``DecryptionKeys/init(jwks:allowing:)``.
public protocol JWKDecryptableAlgorithm: KeyManagementAlgorithm {
    /// A decrypter for this algorithm, if the key's type and its `use`, `key_ops` and `alg`
    /// allow it.
    static func decrypter(for jwk: PrivateJWK) throws(JWKError) -> AnyKeyDecrypter
}

/// Something that can recover a content encryption key with one specific algorithm.
///
/// Decryption is `async` for the same reason signing is: the private key may be in hardware or
/// behind a service.
///
/// A key management algorithm that ships a key in two roles has two types, one conforming to
/// ``KeyEncrypter`` and one to this protocol, named `…Encrypter` and `…Decrypter`.
public protocol KeyDecrypter<Algorithm>: Sendable {
    associatedtype Algorithm: KeyManagementAlgorithm

    var keyID: KeyID? { get }

    /// Returns the content encryption key.
    ///
    /// Throw ``JWEError/decryptionFailed``, and nothing more specific, when the key cannot be
    /// recovered because the cryptography failed. Anything knowable from the header alone
    /// (a missing `epk`, a key of the wrong type) should be reported precisely.
    func decryptKey(_ request: KeyDecryptionRequest) async throws(JWEError) -> Data
}

/// A ``KeyEncrypter`` with its algorithm type erased, for JWEs with several recipients.
public struct AnyKeyEncrypter: Sendable {
    public let algorithm: AlgorithmIdentifier
    public let keyID: KeyID?
    private let encrypt: @Sendable (KeyEncryptionRequest) async throws(JWEError) -> KeyEncryptionResult

    public init<E: KeyEncrypter>(_ encrypter: E) {
        algorithm = E.Algorithm.identifier
        keyID = encrypter.keyID
        encrypt = { (request: KeyEncryptionRequest) async throws(JWEError) in
            try await encrypter.encryptKey(request)
        }
    }

    func encryptKey(_ request: KeyEncryptionRequest) async throws(JWEError) -> KeyEncryptionResult {
        try await encrypt(request)
    }
}

/// A ``KeyDecrypter`` with its algorithm type erased, so that decrypters for different algorithms
/// can be held together and chosen by the `alg` a JWE names.
public struct AnyKeyDecrypter: Sendable {
    public let algorithm: AlgorithmIdentifier
    public let keyID: KeyID?
    private let decrypt: @Sendable (KeyDecryptionRequest) async throws(JWEError) -> Data

    public init<D: KeyDecrypter>(_ decrypter: D) {
        algorithm = D.Algorithm.identifier
        keyID = decrypter.keyID
        decrypt = { (request: KeyDecryptionRequest) async throws(JWEError) in
            try await decrypter.decryptKey(request)
        }
    }

    func decryptKey(_ request: KeyDecryptionRequest) async throws(JWEError) -> Data {
        try await decrypt(request)
    }
}

/// The keys a JWE may be decrypted with.
///
/// This is also the list of acceptable key management algorithms: a recipient is only ever tried
/// with a decrypter whose algorithm equals the `alg` it names.
public struct DecryptionKeys: Sendable {
    public let decrypters: [AnyKeyDecrypter]

    public init(_ decrypters: [AnyKeyDecrypter]) {
        self.decrypters = decrypters
    }

    public init(@DecryptionKeysBuilder _ build: () throws -> [AnyKeyDecrypter]) rethrows {
        decrypters = try build()
    }

    /// Builds decrypters from private JWKs, for the named algorithms only.
    ///
    /// Each key yields a decrypter for each listed algorithm it is suitable for: right key type,
    /// and permitted by the key's `use`, `key_ops` and `alg`. Keys suitable for none are skipped.
    /// Symmetric keys are built with their decrypter's `init(jwk:)`.
    public init(jwks: [PrivateJWK], allowing algorithms: [any JWKDecryptableAlgorithm.Type]) {
        var decrypters: [AnyKeyDecrypter] = []
        for jwk in jwks {
            for algorithm in algorithms {
                do {
                    decrypters.append(try algorithm.decrypter(for: jwk))
                } catch {
                    // A key that suits no algorithm contributes no decrypter, and a JWE needing
                    // it then fails with an error naming its algorithm and key ID.
                    continue
                }
            }
        }
        self.decrypters = decrypters
    }

    /// The key management algorithms a JWE may use with these keys.
    public var algorithms: [AlgorithmIdentifier] {
        var seen: [AlgorithmIdentifier] = []
        for decrypter in decrypters where !seen.contains(decrypter.algorithm) {
            seen.append(decrypter.algorithm)
        }
        return seen
    }

    /// The decrypters to try for a recipient: those for its algorithm and, when it names a key
    /// ID, for that key or for no particular key.
    func candidates(algorithm: AlgorithmIdentifier, keyID: KeyID?) throws(JWEError) -> [AnyKeyDecrypter] {
        let forAlgorithm = decrypters.filter { $0.algorithm == algorithm }
        guard !forAlgorithm.isEmpty else {
            throw .noDecrypterForAlgorithm(algorithm: algorithm, offered: algorithms)
        }
        guard let keyID else {
            return forAlgorithm
        }
        let forKey = forAlgorithm.filter { $0.keyID == nil || $0.keyID == keyID }
        guard !forKey.isEmpty else {
            throw .noDecrypterForKeyID(keyID: keyID, algorithm: algorithm)
        }
        return forKey
    }
}

@resultBuilder
public struct DecryptionKeysBuilder {
    public static func buildExpression<D: KeyDecrypter>(_ decrypter: D) -> [AnyKeyDecrypter] {
        [AnyKeyDecrypter(decrypter)]
    }

    public static func buildExpression(_ decrypter: AnyKeyDecrypter) -> [AnyKeyDecrypter] {
        [decrypter]
    }

    public static func buildExpression(_ decrypters: [AnyKeyDecrypter]) -> [AnyKeyDecrypter] {
        decrypters
    }

    public static func buildExpression(_ keys: DecryptionKeys) -> [AnyKeyDecrypter] {
        keys.decrypters
    }

    public static func buildBlock(_ components: [AnyKeyDecrypter]...) -> [AnyKeyDecrypter] {
        components.flatMap { $0 }
    }

    public static func buildOptional(_ component: [AnyKeyDecrypter]?) -> [AnyKeyDecrypter] {
        component ?? []
    }

    public static func buildEither(first component: [AnyKeyDecrypter]) -> [AnyKeyDecrypter] {
        component
    }

    public static func buildEither(second component: [AnyKeyDecrypter]) -> [AnyKeyDecrypter] {
        component
    }

    public static func buildArray(_ components: [[AnyKeyDecrypter]]) -> [AnyKeyDecrypter] {
        components.flatMap { $0 }
    }
}
