import Foundation
import JOSECore
import JOSEJWK

/// PBES2 key encryption (RFC 7518 §4.8): a key derived from a password with PBKDF2 wraps the
/// content encryption key with AES Key Wrap.
public protocol PBES2Algorithm: KeyManagementAlgorithm {
    static var hash: PBKDF2Hash { get }
    /// The size of the AES Key Wrap key to derive.
    static var keyByteCount: Int { get }
}

/// PBES2 with HMAC SHA-256 and A128KW.
public struct PBES2HS256A128KW: PBES2Algorithm {
    public static let identifier: AlgorithmIdentifier = "PBES2-HS256+A128KW"
    public static let hash = PBKDF2Hash.sha256
    public static let keyByteCount = 16
}

/// PBES2 with HMAC SHA-384 and A192KW.
public struct PBES2HS384A192KW: PBES2Algorithm {
    public static let identifier: AlgorithmIdentifier = "PBES2-HS384+A192KW"
    public static let hash = PBKDF2Hash.sha384
    public static let keyByteCount = 24
}

/// PBES2 with HMAC SHA-512 and A256KW.
public struct PBES2HS512A256KW: PBES2Algorithm {
    public static let identifier: AlgorithmIdentifier = "PBES2-HS512+A256KW"
    public static let hash = PBKDF2Hash.sha512
    public static let keyByteCount = 32
}

extension PBES2Algorithm {
    /// The largest iteration count PBKDF2 accepts here: CommonCrypto takes the count as a
    /// `UInt32`.
    public static var iterationCountLimit: Int {
        Int(clamping: UInt32.max)
    }
}

/// The derivation both directions share.
private struct PBES2Derivation<Algorithm: PBES2Algorithm> {
    let password: Data

    /// The PBKDF2 salt of RFC 7518 §4.8.1.1: the algorithm name, a zero byte, then the salt input.
    private static func salt(from saltInput: Data) -> Data {
        Data(Algorithm.identifier.rawValue.utf8) + [0x00] + saltInput
    }

    func wrappingKey(saltInput: Data, iterations: Int) throws(JWEError) -> Data {
        do {
            return try PlatformPBKDF2(hash: Algorithm.hash).derive(
                password: password,
                salt: Self.salt(from: saltInput),
                iterations: iterations,
                byteCount: Algorithm.keyByteCount
            )
        } catch {
            throw .contentEncryptionFailed(description: "\(Algorithm.identifier) key derivation failed: \(error)")
        }
    }
}

/// Encrypts the content encryption key under a password.
///
/// The iteration count is the only defence a password has against guessing once a token is in
/// an attacker's hands. The default matches what other implementations accept without
/// configuration; raise it if every recipient is known to allow more.
public struct PBES2Encrypter<Algorithm: PBES2Algorithm>: KeyEncrypter {
    public let keyID: KeyID?
    /// The PBKDF2 iteration count written into tokens this encrypter produces.
    public let iterationCount: Int
    private let derivation: PBES2Derivation<Algorithm>

    /// - Parameters:
    ///   - password: The password as bytes; for text, its UTF-8 encoding.
    ///   - iterationCount: Between 1 and ``PBES2Algorithm/iterationCountLimit``.
    public init(password: Data, keyID: KeyID? = nil, iterationCount: Int = 2048) throws(JWEError) {
        guard iterationCount >= 1, iterationCount <= Algorithm.iterationCountLimit else {
            throw .invalidIterationCount(found: iterationCount, maximum: Algorithm.iterationCountLimit)
        }
        derivation = PBES2Derivation(password: password)
        self.keyID = keyID
        self.iterationCount = iterationCount
    }

    public init(password: String, keyID: KeyID? = nil, iterationCount: Int = 2048) throws(JWEError) {
        try self.init(password: Data(password.utf8), keyID: keyID, iterationCount: iterationCount)
    }

    public func encryptKey(_ request: KeyEncryptionRequest) async throws(JWEError) -> KeyEncryptionResult {
        let saltInput = SymmetricKeyMaterial(randomByteCount: 16).rawRepresentation
        let wrappingKey = try derivation.wrappingKey(saltInput: saltInput, iterations: iterationCount)
        let contentKey = request.keyToWrap()
        do {
            return KeyEncryptionResult(
                contentEncryptionKey: contentKey,
                encryptedKey: try AESKeyWrapping(wrappingKey: wrappingKey).wrap(contentKey),
                headerParameters: [
                    "p2s": .string(String(base64URLEncoding: saltInput)),
                    "p2c": .integer(Int64(iterationCount)),
                ]
            )
        } catch {
            throw .contentEncryptionFailed(description: "\(Algorithm.identifier) key wrap failed: \(error)")
        }
    }
}

/// Decrypts the content encryption key under a password.
///
/// A received token chooses its own iteration count, and so the work you do to decrypt it: a
/// token can ask for billions. ``maximumIterationCount`` bounds that, and a token above it is
/// refused before any work is done.
public struct PBES2Decrypter<Algorithm: PBES2Algorithm>: KeyDecrypter {
    /// RFC 7518 §4.8.1.1 requires at least 8 bytes of salt input.
    public static var minimumSaltByteCount: Int {
        8
    }

    public let keyID: KeyID?
    /// The largest iteration count accepted, never above ``PBES2Algorithm/iterationCountLimit``.
    public let maximumIterationCount: Int
    private let derivation: PBES2Derivation<Algorithm>

    /// - Parameters:
    ///   - password: The password as bytes; for text, its UTF-8 encoding.
    ///   - maximumIterationCount: The largest iteration count accepted. Values above
    ///     ``PBES2Algorithm/iterationCountLimit`` are lowered to it.
    public init(password: Data, keyID: KeyID? = nil, maximumIterationCount: Int = 10_000) {
        derivation = PBES2Derivation(password: password)
        self.keyID = keyID
        self.maximumIterationCount = min(maximumIterationCount, Algorithm.iterationCountLimit)
    }

    public init(password: String, keyID: KeyID? = nil, maximumIterationCount: Int = 10_000) {
        self.init(password: Data(password.utf8), keyID: keyID, maximumIterationCount: maximumIterationCount)
    }

    public func decryptKey(_ request: KeyDecryptionRequest) async throws(JWEError) -> Data {
        let saltInput = try request.requiredBytes("p2s", for: Algorithm.identifier)
        guard saltInput.count >= Self.minimumSaltByteCount else {
            throw .saltTooShort(
                algorithm: Algorithm.identifier,
                minimum: Self.minimumSaltByteCount,
                found: saltInput.count
            )
        }
        guard let countValue = request.header["p2c"] else {
            throw .missingHeaderParameter(name: "p2c", algorithm: Algorithm.identifier)
        }
        guard case .integer(let count) = countValue else {
            throw .headerParameterWrongType(name: "p2c", expected: "a positive integer")
        }
        // Checked before any derivation: the count is attacker-controlled, and PBKDF2's cost is
        // linear in it.
        guard count >= 1, count <= Int64(maximumIterationCount) else {
            throw .invalidIterationCount(found: Int(clamping: count), maximum: maximumIterationCount)
        }
        let wrappingKey = try derivation.wrappingKey(saltInput: saltInput, iterations: Int(count))
        return try AESKeyWrapping(wrappingKey: wrappingKey).unwrap(request.encryptedKey)
    }
}
