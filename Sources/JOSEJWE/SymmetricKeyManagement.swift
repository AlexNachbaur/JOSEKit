import Foundation
import JOSECore
import JOSEJWK

#if canImport(CryptoKit)
    import CryptoKit
#else
    import Crypto
#endif

// MARK: - dir

/// Direct use of a shared symmetric key as the content encryption key (RFC 7518 §4.5).
public struct Direct: KeyManagementAlgorithm {
    public static let identifier: AlgorithmIdentifier = "dir"
}

/// The shared key, checked against the content encryption algorithm. Its size depends on `enc`,
/// and so does any restriction from the key's JWK, so both can only be checked once a JWE is
/// being produced or read.
private func directKey(
    _ key: SymmetricKeyMaterial,
    restrictedTo restriction: AlgorithmIdentifier?,
    for request: (contentEncryption: AlgorithmIdentifier, keyByteCount: Int)
) throws(JWEError) -> Data {
    if let restriction {
        guard restriction == request.contentEncryption else {
            throw .contentEncryptionNotPermitted(
                keyAlgorithm: restriction,
                contentEncryption: request.contentEncryption
            )
        }
    }
    guard key.rawRepresentation.count == request.keyByteCount else {
        throw .keyWrongSize(
            algorithm: Direct.identifier,
            expected: request.keyByteCount,
            found: key.rawRepresentation.count
        )
    }
    return key.rawRepresentation
}

/// Checks a `dir` key's JWK restrictions and returns the content encryption algorithm its `alg`
/// restricts it to, if any.
///
/// A `dir` key is the content encryption key, so its JWK may name either `dir` or the content
/// encryption algorithm it is for. RFC 7520 §5.6 does the latter (`"alg": "A128GCM"`).
private func directKeyRestriction(
    _ metadata: JWKMetadata,
    for operation: KeyOperation
) throws(JWKError) -> AlgorithmIdentifier? {
    var checked = metadata
    var restriction: AlgorithmIdentifier?
    if let algorithm = metadata.algorithm, algorithm != Direct.identifier {
        restriction = algorithm
        checked.algorithm = nil
    }
    try checked.requirePermission(for: operation, use: .encryption, algorithm: Direct.identifier)
    return restriction
}

/// Encrypts with a shared key used directly as the content encryption key. The key must be
/// exactly the size the content encryption algorithm needs, and the JWE can have no other
/// recipient.
public struct DirectEncrypter: KeyEncrypter {
    public typealias Algorithm = Direct

    public let keyID: KeyID?
    private let key: SymmetricKeyMaterial
    private let restriction: AlgorithmIdentifier?

    public init(key: SymmetricKeyMaterial, keyID: KeyID? = nil) {
        self.key = key
        self.keyID = keyID
        restriction = nil
    }

    /// Builds an encrypter from a symmetric JWK, honouring its `use` and `key_ops`. Its `alg` may
    /// be `dir` or a content encryption algorithm, which the key is then used with only.
    public init(jwk: SymmetricJWK) throws(JWKError) {
        restriction = try directKeyRestriction(jwk.metadata, for: .encrypt)
        key = jwk.key
        keyID = jwk.metadata.keyID
    }

    public func encryptKey(_ request: KeyEncryptionRequest) async throws(JWEError) -> KeyEncryptionResult {
        guard request.contentEncryptionKey == nil else {
            throw .algorithmRequiresSingleRecipient(algorithm: Algorithm.identifier)
        }
        return KeyEncryptionResult(
            contentEncryptionKey: try directKey(
                key,
                restrictedTo: restriction,
                for: (request.contentEncryption, request.keyByteCount)
            ),
            encryptedKey: Data()
        )
    }
}

/// Decrypts with a shared key used directly as the content encryption key.
public struct DirectDecrypter: KeyDecrypter {
    public typealias Algorithm = Direct

    public let keyID: KeyID?
    private let key: SymmetricKeyMaterial
    private let restriction: AlgorithmIdentifier?

    public init(key: SymmetricKeyMaterial, keyID: KeyID? = nil) {
        self.key = key
        self.keyID = keyID
        restriction = nil
    }

    /// Builds a decrypter from a symmetric JWK, honouring its `use` and `key_ops`. Its `alg` may
    /// be `dir` or a content encryption algorithm, which the key is then used with only.
    public init(jwk: SymmetricJWK) throws(JWKError) {
        restriction = try directKeyRestriction(jwk.metadata, for: .decrypt)
        key = jwk.key
        keyID = jwk.metadata.keyID
    }

    public func decryptKey(_ request: KeyDecryptionRequest) async throws(JWEError) -> Data {
        // RFC 7516 §5.2 step 10: with direct encryption the encrypted key must be empty.
        guard request.encryptedKey.isEmpty else {
            throw .encryptedKeyNotEmpty(algorithm: Algorithm.identifier)
        }
        return try directKey(
            key,
            restrictedTo: restriction,
            for: (request.contentEncryption, request.keyByteCount)
        )
    }
}

// MARK: - AES Key Wrap

/// AES Key Wrap with a key of a fixed size (RFC 7518 §4.4).
public protocol AESKeyWrapAlgorithm: KeyManagementAlgorithm {
    static var keyByteCount: Int { get }
}

public struct A128KW: AESKeyWrapAlgorithm {
    public static let identifier: AlgorithmIdentifier = "A128KW"
    public static let keyByteCount = 16
}

public struct A192KW: AESKeyWrapAlgorithm {
    public static let identifier: AlgorithmIdentifier = "A192KW"
    public static let keyByteCount = 24
}

public struct A256KW: AESKeyWrapAlgorithm {
    public static let identifier: AlgorithmIdentifier = "A256KW"
    public static let keyByteCount = 32
}

/// AES Key Wrap (RFC 3394) under one key-wrapping key.
struct AESKeyWrapping {
    let wrappingKey: Data

    func wrap(_ key: Data) throws -> Data {
        try AES.KeyWrap.wrap(SymmetricKey(data: key), using: SymmetricKey(data: wrappingKey))
    }

    func unwrap(_ wrapped: Data) throws(JWEError) -> Data {
        do {
            return try AES.KeyWrap.unwrap(wrapped, using: SymmetricKey(data: wrappingKey)).withUnsafeBytes { Data($0) }
        } catch {
            throw .decryptionFailed
        }
    }
}

/// A key-wrapping key, checked to be exactly the size `algorithm` needs.
private func wrappingKey(
    _ key: SymmetricKeyMaterial,
    for algorithm: AlgorithmIdentifier,
    byteCount: Int
) throws(JWKError) -> Data {
    guard key.rawRepresentation.count == byteCount else {
        throw .keyWrongSize(algorithm: algorithm, expectedByteCount: byteCount, found: key.rawRepresentation.count)
    }
    return key.rawRepresentation
}

/// Wraps the content encryption key with AES Key Wrap under a shared key.
public struct AESKeyWrapEncrypter<Algorithm: AESKeyWrapAlgorithm>: KeyEncrypter {
    public let keyID: KeyID?
    private let key: Data

    public init(key: SymmetricKeyMaterial, keyID: KeyID? = nil) throws(JWKError) {
        self.key = try wrappingKey(key, for: Algorithm.identifier, byteCount: Algorithm.keyByteCount)
        self.keyID = keyID
    }

    /// Builds an encrypter from a symmetric JWK, honouring its `use`, `key_ops` and `alg`.
    public init(jwk: SymmetricJWK) throws(JWKError) {
        try jwk.metadata.requirePermission(for: .wrapKey, use: .encryption, algorithm: Algorithm.identifier)
        try self.init(key: jwk.key, keyID: jwk.metadata.keyID)
    }

    public func encryptKey(_ request: KeyEncryptionRequest) async throws(JWEError) -> KeyEncryptionResult {
        let contentKey = request.keyToWrap()
        do {
            return KeyEncryptionResult(
                contentEncryptionKey: contentKey,
                encryptedKey: try AESKeyWrapping(wrappingKey: key).wrap(contentKey)
            )
        } catch {
            throw .contentEncryptionFailed(description: "\(Algorithm.identifier) key wrap failed: \(error)")
        }
    }
}

/// Unwraps the content encryption key with AES Key Wrap under a shared key.
public struct AESKeyWrapDecrypter<Algorithm: AESKeyWrapAlgorithm>: KeyDecrypter {
    public let keyID: KeyID?
    private let key: Data

    public init(key: SymmetricKeyMaterial, keyID: KeyID? = nil) throws(JWKError) {
        self.key = try wrappingKey(key, for: Algorithm.identifier, byteCount: Algorithm.keyByteCount)
        self.keyID = keyID
    }

    /// Builds a decrypter from a symmetric JWK, honouring its `use`, `key_ops` and `alg`.
    public init(jwk: SymmetricJWK) throws(JWKError) {
        try jwk.metadata.requirePermission(for: .unwrapKey, use: .encryption, algorithm: Algorithm.identifier)
        try self.init(key: jwk.key, keyID: jwk.metadata.keyID)
    }

    public func decryptKey(_ request: KeyDecryptionRequest) async throws(JWEError) -> Data {
        try AESKeyWrapping(wrappingKey: key).unwrap(request.encryptedKey)
    }
}

// MARK: - AES-GCM key wrap

/// Key encryption with AES GCM (RFC 7518 §4.7). The IV and tag travel in the header.
public protocol AESGCMKeyWrapAlgorithm: KeyManagementAlgorithm {
    static var keyByteCount: Int { get }
}

public struct A128GCMKW: AESGCMKeyWrapAlgorithm {
    public static let identifier: AlgorithmIdentifier = "A128GCMKW"
    public static let keyByteCount = 16
}

public struct A192GCMKW: AESGCMKeyWrapAlgorithm {
    public static let identifier: AlgorithmIdentifier = "A192GCMKW"
    public static let keyByteCount = 24
}

public struct A256GCMKW: AESGCMKeyWrapAlgorithm {
    public static let identifier: AlgorithmIdentifier = "A256GCMKW"
    public static let keyByteCount = 32
}

/// Encrypts the content encryption key with AES GCM under a shared key.
public struct AESGCMKeyWrapEncrypter<Algorithm: AESGCMKeyWrapAlgorithm>: KeyEncrypter {
    public let keyID: KeyID?
    private let key: Data

    public init(key: SymmetricKeyMaterial, keyID: KeyID? = nil) throws(JWKError) {
        self.key = try wrappingKey(key, for: Algorithm.identifier, byteCount: Algorithm.keyByteCount)
        self.keyID = keyID
    }

    /// Builds an encrypter from a symmetric JWK, honouring its `use`, `key_ops` and `alg`.
    public init(jwk: SymmetricJWK) throws(JWKError) {
        try jwk.metadata.requirePermission(for: .wrapKey, use: .encryption, algorithm: Algorithm.identifier)
        try self.init(key: jwk.key, keyID: jwk.metadata.keyID)
    }

    public func encryptKey(_ request: KeyEncryptionRequest) async throws(JWEError) -> KeyEncryptionResult {
        let contentKey = request.keyToWrap()
        // A fresh random 96-bit IV for every wrap, as RFC 7518 §4.7.1.1 requires: reusing an IV
        // with the same key breaks GCM completely.
        let iv = SymmetricKeyMaterial(randomByteCount: 12).rawRepresentation
        let (encryptedKey, tag) = try AESGCM(key: key).seal(contentKey, nonce: iv, aad: Data())
        return KeyEncryptionResult(
            contentEncryptionKey: contentKey,
            encryptedKey: encryptedKey,
            headerParameters: [
                "iv": .string(String(base64URLEncoding: iv)), "tag": .string(String(base64URLEncoding: tag)),
            ]
        )
    }
}

/// Decrypts the content encryption key with AES GCM under a shared key.
public struct AESGCMKeyWrapDecrypter<Algorithm: AESGCMKeyWrapAlgorithm>: KeyDecrypter {
    public let keyID: KeyID?
    private let key: Data

    public init(key: SymmetricKeyMaterial, keyID: KeyID? = nil) throws(JWKError) {
        self.key = try wrappingKey(key, for: Algorithm.identifier, byteCount: Algorithm.keyByteCount)
        self.keyID = keyID
    }

    /// Builds a decrypter from a symmetric JWK, honouring its `use`, `key_ops` and `alg`.
    public init(jwk: SymmetricJWK) throws(JWKError) {
        try jwk.metadata.requirePermission(for: .unwrapKey, use: .encryption, algorithm: Algorithm.identifier)
        try self.init(key: jwk.key, keyID: jwk.metadata.keyID)
    }

    public func decryptKey(_ request: KeyDecryptionRequest) async throws(JWEError) -> Data {
        let iv = try request.requiredBytes("iv", for: Algorithm.identifier)
        let tag = try request.requiredBytes("tag", for: Algorithm.identifier)
        guard iv.count == 12 else {
            throw .wrongInitializationVectorSize(algorithm: Algorithm.identifier, expected: 12, found: iv.count)
        }
        guard tag.count == 16 else {
            throw .wrongAuthenticationTagSize(algorithm: Algorithm.identifier, expected: 16, found: tag.count)
        }
        return try AESGCM(key: key).open(request.encryptedKey, tag: tag, nonce: iv, aad: Data())
    }
}
