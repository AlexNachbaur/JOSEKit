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

/// The shared key, checked against the size the content encryption algorithm needs. That size
/// depends on `enc`, so it can only be checked once a JWE is being produced or read.
private func directKey(_ key: SymmetricKeyMaterial, byteCount: Int) throws(JWEError) -> Data {
    guard key.rawRepresentation.count == byteCount else {
        throw .keyWrongSize(algorithm: Direct.identifier, expected: byteCount, found: key.rawRepresentation.count)
    }
    return key.rawRepresentation
}

/// Encrypts with a shared key used directly as the content encryption key. The key must be
/// exactly the size the content encryption algorithm needs, and the JWE can have no other
/// recipient.
public struct DirectEncrypter: KeyEncrypter {
    public typealias Algorithm = Direct

    public let keyID: KeyID?
    private let key: SymmetricKeyMaterial

    public init(key: SymmetricKeyMaterial, keyID: KeyID? = nil) {
        self.key = key
        self.keyID = keyID
    }

    /// Builds an encrypter from a symmetric JWK, honouring its `use`, `key_ops` and `alg`.
    public init(jwk: SymmetricJWK) throws(JWKError) {
        try jwk.metadata.requirePermission(for: .encrypt, use: .encryption, algorithm: Algorithm.identifier)
        self.init(key: jwk.key, keyID: jwk.metadata.keyID)
    }

    public func encryptKey(_ request: KeyEncryptionRequest) async throws(JWEError) -> KeyEncryptionResult {
        guard request.contentEncryptionKey == nil else {
            throw .algorithmRequiresSingleRecipient(algorithm: Algorithm.identifier)
        }
        return KeyEncryptionResult(
            contentEncryptionKey: try directKey(key, byteCount: request.keyByteCount),
            encryptedKey: Data()
        )
    }
}

/// Decrypts with a shared key used directly as the content encryption key.
public struct DirectDecrypter: KeyDecrypter {
    public typealias Algorithm = Direct

    public let keyID: KeyID?
    private let key: SymmetricKeyMaterial

    public init(key: SymmetricKeyMaterial, keyID: KeyID? = nil) {
        self.key = key
        self.keyID = keyID
    }

    /// Builds a decrypter from a symmetric JWK, honouring its `use`, `key_ops` and `alg`.
    public init(jwk: SymmetricJWK) throws(JWKError) {
        try jwk.metadata.requirePermission(for: .decrypt, use: .encryption, algorithm: Algorithm.identifier)
        self.init(key: jwk.key, keyID: jwk.metadata.keyID)
    }

    public func decryptKey(_ request: KeyDecryptionRequest) async throws(JWEError) -> Data {
        // RFC 7516 §5.2 step 10: with direct encryption the encrypted key must be empty.
        guard request.encryptedKey.isEmpty else {
            throw .encryptedKeyNotEmpty(algorithm: Algorithm.identifier)
        }
        return try directKey(key, byteCount: request.keyByteCount)
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

struct AESKeyWrapping {
    private init() {}

    static func wrap(_ key: Data, with wrappingKey: Data) throws -> Data {
        try AES.KeyWrap.wrap(SymmetricKey(data: key), using: SymmetricKey(data: wrappingKey))
    }

    static func unwrap(_ wrapped: Data, with wrappingKey: Data) throws(JWEError) -> Data {
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
                encryptedKey: try AESKeyWrapping.wrap(contentKey, with: key)
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
        try AESKeyWrapping.unwrap(request.encryptedKey, with: key)
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
        let (encryptedKey, tag) = try AESGCM.seal(contentKey, key: key, nonce: iv, aad: Data())
        return KeyEncryptionResult(
            contentEncryptionKey: contentKey,
            encryptedKey: encryptedKey,
            headerParameters: ["iv": .string(Base64URL.encode(iv)), "tag": .string(Base64URL.encode(tag))]
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
        return try AESGCM.open(request.encryptedKey, tag: tag, key: key, nonce: iv, aad: Data())
    }
}
