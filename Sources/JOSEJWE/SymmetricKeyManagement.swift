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

/// Encrypts and decrypts with a shared key used directly. The key must be exactly the size the
/// content encryption algorithm needs.
public struct DirectKey: KeyEncrypter, KeyDecrypter {
    public typealias Algorithm = Direct

    public let keyID: KeyID?
    private let key: SymmetricKeyMaterial

    public init(key: SymmetricKeyMaterial, keyID: KeyID? = nil) {
        self.key = key
        self.keyID = keyID
    }

    private func checkedKey(byteCount: Int) throws(JWEError) -> Data {
        guard key.rawRepresentation.count == byteCount else {
            throw .keyWrongSize(
                algorithm: Algorithm.identifier,
                expected: byteCount,
                found: key.rawRepresentation.count
            )
        }
        return key.rawRepresentation
    }

    public func encryptKey(_ request: KeyEncryptionRequest) throws(JWEError) -> KeyEncryptionResult {
        guard request.contentEncryptionKey == nil else {
            throw .algorithmRequiresSingleRecipient(algorithm: Algorithm.identifier)
        }
        return KeyEncryptionResult(
            contentEncryptionKey: try checkedKey(byteCount: request.keyByteCount),
            encryptedKey: Data()
        )
    }

    public func decryptKey(_ request: KeyDecryptionRequest) async throws(JWEError) -> Data {
        // RFC 7516 §5.2 step 10: with direct encryption the encrypted key must be empty.
        guard request.encryptedKey.isEmpty else {
            throw .encryptedKeyNotEmpty(algorithm: Algorithm.identifier)
        }
        return try checkedKey(byteCount: request.keyByteCount)
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

/// Wraps and unwraps the content encryption key with AES Key Wrap under a shared key.
public struct AESKeyWrapKey<Algorithm: AESKeyWrapAlgorithm>: KeyEncrypter, KeyDecrypter {
    public let keyID: KeyID?
    private let key: Data

    public init(key: SymmetricKeyMaterial, keyID: KeyID? = nil) throws(JWEError) {
        guard key.rawRepresentation.count == Algorithm.keyByteCount else {
            throw .keyWrongSize(
                algorithm: Algorithm.identifier,
                expected: Algorithm.keyByteCount,
                found: key.rawRepresentation.count
            )
        }
        self.key = key.rawRepresentation
        self.keyID = keyID
    }

    public func encryptKey(_ request: KeyEncryptionRequest) throws(JWEError) -> KeyEncryptionResult {
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

/// Encrypts and decrypts the content encryption key with AES GCM under a shared key.
public struct AESGCMKeyWrapKey<Algorithm: AESGCMKeyWrapAlgorithm>: KeyEncrypter, KeyDecrypter {
    public let keyID: KeyID?
    private let key: Data

    public init(key: SymmetricKeyMaterial, keyID: KeyID? = nil) throws(JWEError) {
        guard key.rawRepresentation.count == Algorithm.keyByteCount else {
            throw .keyWrongSize(
                algorithm: Algorithm.identifier,
                expected: Algorithm.keyByteCount,
                found: key.rawRepresentation.count
            )
        }
        self.key = key.rawRepresentation
        self.keyID = keyID
    }

    public func encryptKey(_ request: KeyEncryptionRequest) throws(JWEError) -> KeyEncryptionResult {
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
